/*
 * ChatMD-Backend is the API part of ChatMD.
 * It works with HTTP for the authentication part and WebSocket for the rest.
 *
 * It is important to consider that the HTTP part runs on port 8080
 * and the WS part runs on port 8081
 *
 * Here are some URIs:
 * POST /auth/register
 * fields: username (string), password (string)
 *
 * POST /auth/login
 * fields: username (string), password (string)
 *
 * WebSocket: You must put an authorization header (Bearer token)
 *   to be able to connect. Else you'll be kicked right off without any message.
 *
 * To send a message, you just send a string to the WS and let the magic does the rest!
 * The server will send you a response at an event (message send, or connect/disconnect)
 */

require('dotenv').config()
const app = require('express')()
const formidable = require('express-formidable')
const cors = require('cors')
const argon2 = require('argon2')
const WebSocket = require('ws')
const wss = new WebSocket.Server({ port: 8081 })
const mongodb = require('mongodb')
const mongo = new mongodb.MongoClient(process.env.DB_ADDRESS, {
  useNewUrlParser: true,
})
const http = require('http').createServer(app)

app.use(
  formidable({
    maxFileSize: 5 * 1024 * 1024,
    maxFieldsSize: 16 * 1024 * 1024,
    multiples: true,
  })
)
app.use(cors())

app.set('trust proxy', true)

// Listen to HTTP
http.listen(8080, async () => {
  const client = await mongo.connect()
  const db = client.db('chatmd-dev')

  // [POST] Register
  app.post('/auth/register', async (req, res) => {
    let session = req.headers.authorization
      ? req.headers.authorization.split(' ')[1].trim()
      : null
    if (session != null) return res.status(401).json(returnCode(401, 1))

    let username = req.fields.username
    let password = req.fields.password
    if (username == null || password == null)
      return res.status(401).json(returnCode(401, 2))

    let user = await db.collection('users').findOne({
      username: username,
    })

    if (user != null) return res.status(418).json(returnCode(418, 10))

    const hash = await argon2.hash(password)

    let token = generateToken()

    await db.collection('users').insertOne({
      username: username,
      password: hash,
      session: token,
      active: false,
    })

    res.status(200).json(returnCode(200, 200, { session: token }))
  })

  // [POST] Login
  app.post('/auth/login', async (req, res) => {
    let session = req.headers.authorization
      ? req.headers.authorization.split(' ')[1].trim()
      : null
    if (session != null) return res.status(401).json(returnCode(401, 1))

    let username = req.fields.username
    let password = req.fields.password
    if (username == null || password == null)
      return res.status(401).json(returnCode(401, 2))

    let user = await db.collection('users').findOne({
      username: username,
    })

    if (user == null) return res.status(418).json(returnCode(418, 11))

    const verify = await argon2.verify(user.password, password)
    if (!verify) return res.status(401).json(returnCode(401, 11))

    let token = generateToken()

    await db.collection('users').findOneAndUpdate(
      {
        username: username,
      },
      {
        $set: {
          session: token,
        },
      }
    )

    res.status(200).json(returnCode(200, 200, { session: token }))
  })

  // [PUT] Update username
  app.put('/account/update/username', async (req, res) => {
    let session = req.headers.authorization
      ? req.headers.authorization.split(' ')[1].trim()
      : null
    if (session == null) return res.status(401).json(returnCode(401, 0))

    let new_username = req.fields.username

    let usr = await db.collection('users').findOne({
      session: session,
    })
    if (usr == null) return res.status(401).json(returnCode(401, 0))

    let checkUser = await db.collection('users').findOne({
      username: new_username,
    })
    if (checkUser != null)
      return res.status(401).json(returnCode(401, 'Username already taken'))

    // Updates the account name
    await db.collection('users').findOneAndUpdate(
      {
        session: session,
      },
      {
        $set: {
          username: new_username,
        },
      }
    )

    // Updates the messages
    await db.collection('messages').updateMany(
      {
        user: usr._id,
      },
      {
        $set: {
          username: new_username,
        },
      }
    )

    res.status(200).json(returnCode(200, 200))
  })

  // [DELETE] Logout
  app.delete('/auth/logout', async (req, res) => {
    let session = req.headers.authorization
      ? req.headers.authorization.split(' ')[1].trim()
      : null
    if (session == null) return res.status(401).json(returnCode(401, 0))

    let usr = await db.collection('users').findOne({
      session: session,
    })
    if (usr == null) return res.status(401).json(returnCode(401, 0))

    await db.collection('users').findOneAndUpdate(
      {
        session: session,
      },
      {
        $set: {
          session: null,
          active: false,
        },
      }
    )

    res.status(200).json(returnCode(200, 200))
  })

  app.all('*', (_, res) => {
    res.status(404).json(returnCode(404, 'you got lost man :/'))
  })

  // WebSocket
  wss.on('connection', async (ws, req) => {
    let token = req.headers['authorization']
      ? req.headers['authorization'].split(' ')[1].trim()
      : null
    if (token == null) {
      return ws.terminate()
    }

    let user = await db.collection('users').findOne({
      session: token,
    })

    if (user == null) {
      return ws.terminate()
    }
    await db.collection('users').findOneAndUpdate(
      {
        session: token,
      },
      {
        $set: {
          active: true,
        },
      }
    )
    let awaitDB = db.watch()
    let messages = await db
      .collection('messages')
      .find({})
      .sort({ at: -1 })
      .limit(50)
      .toArray()
    if (messages != null) {
      let array = new Array()
      for (let i = 0; i < messages.length; i++) {
        let obj = {
          username: messages[i].username,
          message: messages[i].message,
          at: messages[i].at,
        }
        array.push(obj)
      }
      ws.send(JSON.stringify(array))
    }

    ws.on('message', async (data) => {
      let now = Date.now()
      await db.collection('messages').insertOne({
        user: user._id,
        username: user.username,
        message: data.toString(),
        at: now,
      })
    })

    ws.on('close', async () => {
      await db.collection('users').findOneAndUpdate(
        {
          session: token,
        },
        {
          $set: {
            active: false,
          },
        }
      )
      ws.terminate()
    })

    // This part should be at the end because the
    // this loop is blocking the thread and is "infinite" (until connection is closed)
    for await (const change of awaitDB) {
      if (change.operationType == 'update') {
        if (change.ns.coll == 'users') {
          let usr = await db.collection('users').findOne({
            _id: new mongodb.ObjectId(change.documentKey._id),
          })

          // If the user is the same as the one that is connected and the session is null
          // kill it.
          if (
            usr._id.toString() == user._id.toString() &&
            usr.session == null
          ) {
            ws.send(JSON.stringify({ type: 'logout' }))
            return ws.terminate()
          }
          ws.send(
            JSON.stringify({
              type: 'event',
              data: {
                event: usr.active ? 'Join' : 'Leave',
                username: usr.username,
                at: Date.now(),
              },
            })
          )
        }
      }

      if (change.operationType == 'insert') {
        if (change.ns.coll == 'messages') {
          let message = change.fullDocument
          ws.send(
            JSON.stringify({
              type: 'message',
              data: {
                username: message.username,
                message: message.message,
                at: message.at,
              },
            })
          )
        }
      }
    }
  })
})

function returnCode(code, messageId, json) {
  let message
  switch (messageId) {
    case 0:
      message = 'You need to be logged in to do this.'
      break
    case 1:
      message = 'You need to be disconnected to do this.'
      break
    case 2:
      message = 'Incorrect data sent'
      break
    case 10:
      message = 'User already exists'
      break
    case 11:
      message = "User doesn't exist"
      break
    case 200:
      message = 'Ok!'
      break
    default:
      message = messageId
  }

  if (json == null)
    return {
      code: code,
      message: message,
    }
  else {
    return {
      code: code,
      message: message,
      data: json,
    }
  }
}

function generateToken() {
  return require('crypto').randomBytes(64).toString('hex')
}
