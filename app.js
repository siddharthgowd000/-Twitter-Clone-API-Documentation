const express = require("express");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const path = require("path");

const app = express();
app.use(express.json());

const dbPath = path.join(__dirname, "twitterClone.db");
let db = null;

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(3000, () => {
      console.log("Server Running at http://localhost:3000/");
    });
  } catch (e) {
    console.log(`DB Error : ${e.message}`);
    process.exit(1);
  }
};

initializeDBAndServer();

const authenticateToken = (request, response, next) => {
  let jwtToken;
  const authHeader = request.headers["authorization"];
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
  }
  if (authHeader === undefined) {
    response.status(401);
    response.send("Invalid JWT Token");
  } else {
    jwt.verify(jwtToken, "MY_SECRET_TOKEN12", async (error, payload) => {
      if (error) {
        response.status(401);
        response.send("Invalid JWT Token");
      } else {
        request.username = payload.username;
        next();
      }
    });
  }
};

app.post("/register/", async (request, response) => {
  const { username, password, name, gender } = request.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const getUsernameQuery = `SELECT * FROM user WHERE username = "${username}";`;
  const getUsername = await db.get(getUsernameQuery);

  if (getUsername === undefined) {
    if (password.length < 6) {
      response.status(400);
      response.send("Password is too short");
    } else {
      const createUserQuery = `INSERT INTO
            user(username,password,name,gender) 
            VALUES ('${username}','${hashedPassword}','${name}','${gender}');`;
      const createUser = await db.run(createUserQuery);
      const newUserId = createUser.lastID;
      response.status(200);
      response.send("User created successfully");
    }
  } else {
    response.status(400);
    response.send("User already exists");
  }
});

app.post("/login/", async (request, response) => {
  const { username, password } = request.body;

  const getUserQuery = `SELECT * FROM user WHERE username="${username}";`;
  const getUser = await db.get(getUserQuery);
  if (getUser !== undefined) {
    const passwordMatch = await bcrypt.compare(
      request.body.password,
      getUser.password
    );
    if (passwordMatch === true) {
      const payload = {
        username: username,
      };
      const jwtToken = jwt.sign(payload, "MY_SECRET_TOKEN12");
      response.send({ jwtToken });
    } else {
      response.status(400);
      response.send("Invalid password");
    }
  } else {
    response.status(400);
    response.send("Invalid user");
  }
});

app.get("/user/tweets/feed/", authenticateToken, async (request, response) => {
  const { username } = request;
  const getTweetsQuery = `SELECT U.username, T.tweet, T.date_time as dateTime
    FROM tweet T
    JOIN user U ON T.user_id = U.user_id
    WHERE T.user_id IN (
      SELECT following_user_id
      FROM follower
      WHERE follower_user_id = (
        SELECT user_id FROM user WHERE username = "${username}"
      )
    )
    ORDER BY T.date_time DESC
    LIMIT 4 ;
                            `;
  const getTweets = await db.all(getTweetsQuery);
  response.send(getTweets);
});

app.get("/user/following/", authenticateToken, async (request, response) => {
  const { username } = request;
  const getFollowingQuery = `SELECT U.name
                           FROM user U
                           JOIN follower F ON U.user_id = F.following_user_id
                           WHERE F.follower_user_id = (SELECT user_id FROM user WHERE username = "${username}");`;

  const getFollowing = await db.all(getFollowingQuery);
  response.send(getFollowing);
});

app.get("/user/followers/", authenticateToken, async (request, response) => {
  const { username } = request;
  const getFollowersQuery = `SELECT U.name
                                  FROM user U
                                  JOIN follower F ON U.user_id = F.follower_user_id
                                  WHERE F.following_user_id = (SELECT user_id FROM user WHERE username = "${username}")`;
  const getFollowers = await db.all(getFollowersQuery);
  response.send(getFollowers);
});

app.get("/tweets/:tweetId/", authenticateToken, async (request, response) => {
  const { username } = request;
  const { tweetId } = request.params;
  const checkFollowQuery = `SELECT EXISTS(
                                SELECT 1
                                FROM follower F
                                JOIN tweet T ON  F.following_user_id = T.user_id
                                WHERE F.follower_user_id = (SELECT user_id
                                                                FROM user
                                                                WHERE username="${username}") AND T.tweet_id = ${tweetId}) AS follows;`;
  const checkFollow = await db.get(checkFollowQuery);
  if (checkFollow.follows === 0) {
    response.status(401);
    response.send("Invalid Request");
  } else {
    const getTweetQuery = `SELECT T.tweet, (SELECT COUNT(*) FROM like WHERE tweet_id = T.tweet_id) AS likes, (SELECT COUNT(*) FROM reply WHERE tweet_id = T.tweet_id) AS replies, T.date_time as dateTime
                                FROM tweet T
                                WHERE T.tweet_id = ${tweetId}; `;
    const getTweet = await db.get(getTweetQuery);
    response.send(getTweet);
  }
});

app.get(
  "/tweets/:tweetId/likes/",
  authenticateToken,
  async (request, response) => {
    const { username } = request;
    const { tweetId } = request.params;
    const checkFollowQuery = `SELECT EXISTS(
                                SELECT 1
                                FROM follower F
                                JOIN tweet T ON  F.following_user_id = T.user_id
                                WHERE F.follower_user_id = (SELECT user_id
                                                                FROM user
                                                                WHERE username="${username}") AND T.tweet_id = ${tweetId}) AS follows;`;
    const checkFollow = await db.get(checkFollowQuery);
    if (checkFollow.follows === 0) {
      response.status(401);
      response.send("Invalid Request");
    } else {
      const getUserLikesQuery = `SELECT U.username 
                                FROM user U
                                JOIN like L ON U.user_id = L.user_id
                                WHERE L.tweet_id = ${tweetId}; `;
      const getUserLikes = await db.all(getUserLikesQuery);
      const usernames = getUserLikes.map((user) => user.username);
      response.send({ likes: usernames });
    }
  }
);

app.get(
  "/tweets/:tweetId/replies/",
  authenticateToken,
  async (request, response) => {
    const { username } = request;
    const { tweetId } = request.params;
    const checkFollowQuery = `SELECT EXISTS(
                                SELECT 1
                                FROM follower F
                                JOIN tweet T ON  F.following_user_id = T.user_id
                                WHERE F.follower_user_id = (SELECT user_id
                                                                FROM user
                                                                WHERE username="${username}") AND T.tweet_id = ${tweetId}) AS follows;`;
    const checkFollow = await db.get(checkFollowQuery);

    if (checkFollow.follows === 0) {
      response.status(401);
      response.send("Invalid Request");
    } else {
      const tweetQuery = `SELECT * FROM tweet WHERE tweet_id = ${tweetId};`;
      const tweet = await db.get(tweetQuery);
      const getReplyQuery = `SELECT  U.username as name, R.reply as reply
                                FROM reply R
                                JOIN user U ON R.user_id = U.user_id
                                JOIN tweet T ON R.tweet_id = T.tweet_id
                                WHERE R.tweet_id = ${tweetId};`;
      const replies = await db.all(getReplyQuery);

      const formattedReplies = replies.map((reply) => ({
        name: reply.name,
        reply: reply.reply,
      }));
      const result = {
        tweet: tweet,
        replies: formattedReplies,
      };

      response.send(result);
    }
  }
);

app.get("/user/tweets/", authenticateToken, async (request, response) => {
  const { username } = request;
  const userIdQuery = `SELECT user_id
                    FROM user
                    WHERE username = "${username}";`;
  const userId = db.get(userIdQuery);
  const getTweetsQuery = `SELECT 
      T.tweet,
      (SELECT COUNT(*) FROM like WHERE tweet_id = T.tweet_id) AS likes,
      (SELECT COUNT(*) FROM reply WHERE tweet_id = T.tweet_id) AS replies,
      T.date_time as dateTime
    FROM tweet T
    WHERE T.user_id = (SELECT user_id FROM user WHERE username = "${username}");`;
  const getTweets = await db.all(getTweetsQuery);
  response.send(getTweets);
});

app.post("/user/tweets/", authenticateToken, async (request, response) => {
  const { username } = request; // Added line to extract username
  const { tweet } = request.body;
  const userIdQuery = `SELECT user_id FROM user WHERE username = "${username}"`; // Fixed query
  const userIdResult = await db.get(userIdQuery);
  const createTweetQuery = `INSERT INTO tweet (tweet, user_id, date_time)
                          VALUES (?, ?, datetime('now'))`;
  await db.run(createTweetQuery, [tweet, userIdResult.user_id]);
  response.send("Created a Tweet");
});

app.delete(
  "/tweets/:tweetId/",
  authenticateToken,
  async (request, response) => {
    const { username } = request;
    const { tweetId } = request.params;
    const checkTweetQuery = `
                                    SELECT *
                                    FROM tweet
                                    WHERE tweet_id = ${tweetId} AND user_id = (SELECT user_id
                                                                                    FROM user
                                                                                    WHERE username = "${username}"); `;
    const checkTweet = await db.get(checkTweetQuery);
    if (checkTweet === undefined) {
      response.status(401);
      response.send("Invalid Request");
    } else {
      const deleteTweetQuery = `DELETE FROM tweet WHERE tweet_id = ${tweetId};`;
      const deleteTweet = await db.run(deleteTweetQuery);
      response.send("Tweet Removed");
    }
  }
);

module.exports = app;
