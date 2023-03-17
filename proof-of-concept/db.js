import Knex from 'knex'
import bcrypt from 'bcrypt'

import {
  generateSigningKeyPair,
  generateEncryptingKeyPair,
  keyPairToJWK,
  keyPairFromJWK,
} from './crypto.js'

const knex = Knex({
  client: 'better-sqlite3',
  connection: {
    filename: process.env.DATABASE_FILE || ':memory:'
  },
  asyncStackTraces: true,
})
export { knex }
await knex.migrate.latest()




const db = {
  async getAllSessions(){
    return await knex.select('*').from('sessions')
  },
  async getAllUsers(){
    return await knex.select('*').from('users')
  },
  async createUser({ username, password }){
    const passwordHash = await bcrypt.hash(password, 10)
    // const { publicKey, privateKey } = await generateSigningKeyPair()
    const signingKeyPair = await generateSigningKeyPair()
    const did = createDidWeb()
    const signingJWK = await keyPairToJWK(signingKeyPair)
    const encryptingJWK = await keyPairToJWK(await generateEncryptingKeyPair())

    const [user] = await knex
      .insert({
        created_at: new Date,
        username,
        password_hash: passwordHash,
        signing_jwk: signingJWK,
        encrypting_jwk: encryptingJWK,
      })
      .into('users')
      .returning('id')
      .catch(error => {
        if (error.message.includes('UNIQUE constraint failed: users.username')){
          throw new Error(`a user with the username ${username} already exists.`)
        }
        throw error
      })
    return await this.getUserById({ id: user.id })
  },

  async getUserById({
    id,
    select = ['id', 'username', 'created_at', 'signing_jwk'],
  }){
    return await knex
      .select(select)
      .from('users')
      .where({ id })
      .first()
      .then(userRecordToUser)
  },

  async getUserByUsername({
    username,
    select = ['id', 'username', 'created_at', 'signing_jwk'],
  }){
    return await knex
      .select(select)
      .from('users')
      .where({ username })
      .first()
      .then(userRecordToUser)
  },

  async authenticateUser({username, password}){
    const record = await this.getUserByUsername({
      username,
      select: ['id', 'password_hash']
    })
    if (!record) return
    const match = await bcrypt.compare(password, record.password_hash);
    if (match) return await this.getUserById({ id: record.id })
  }
}


export default db


async function userRecordToUser(record){
  if (!record) return
  const user = {...record}
  console.log({ user })
  deserializeKeyPairs(user, 'signing_jwk')
  deserializeKeyPairs(user, 'encrypting_jwk')
  // if (user.signing_jwk) user.signing_jwk = await keyPairFromJWK(user.signing_jwk)
  // if (user.encrypting_jwk) user.encrypting_jwk = await keyPairFromJWK(user.encrypting_jwk)
  console.log({ user })
  return user
}

async function deserializeKeyPairs(user, prop){
  user[prop] &&= await keyPairFromJWK(JSON.parse(user[prop]))
}