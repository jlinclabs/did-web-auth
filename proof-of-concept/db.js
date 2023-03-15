import Knex from 'knex'
import bcrypt from 'bcrypt'

import { generateKeyPair, keyToJWK, JWKToKey } from './crypto.js'

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
    return await knex.select('*').from('users').then(users =>
      users.map(user => ({
        ...user,
        public_key: JSON.parse(user.public_key),
        private_key: JSON.parse(user.private_key),
      }))
    )
  },
  async createUser({ username, password }){
    const passwordHash = await bcrypt.hash(password, 10)
    const { publicKey, privateKey } = await generateKeyPair()
    const [user] = await knex
      .insert({
        created_at: new Date,
        username,
        password_hash: passwordHash,
        public_key: await keyToJWK(publicKey),
        private_key: await keyToJWK(privateKey),
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
    select = ['id', 'username', 'created_at', 'public_key'],
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
    select = ['id', 'username', 'created_at', 'public_key'],
  }){
    return await knex
      .select(select)
      .from('users')
      .where({ username })
      .first()
      .then(userRecordToUser)
  },

  async authenticateUser({username, password}){
    const record = await this.getUserByUsername(username, ['id', 'password_hash'])
    if (!record) return
    const match = await bcrypt.compare(password, record.password_hash);
    if (match) return await this.getUserById({ id: record.id })
  }
}


export default db





async function userRecordToUser(record){
  if (!record) return
  const user = {...record}
  if (user.public_key)
    // user.public_key = await JWKToKey(JSON.parse(user.public_key))
    user.public_key = JSON.parse(user.public_key)

  return user
}