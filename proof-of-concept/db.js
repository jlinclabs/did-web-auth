/*
 * Database
 *
 *
 */
import Knex from 'knex'
import bcrypt from 'bcrypt'
import e from 'express'

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
    return await knex
      .select('*')
      .from('sessions')
  },
  async getAllUsers(){
    return await knex
      .select('*')
      .from('users')
  },
  async createUser({ username, password }){
    const passwordHash = await bcrypt.hash(password, 10)
    const [user] = await knex
      .insert({
        created_at: new Date,
        username,
        password_hash: passwordHash,
      })
      .into('users')
      .returning(
        'id',
        'created_at',
        'username',
      )
      .catch(error => {
        if (error.message.includes('UNIQUE constraint failed: users.username')){
          throw new Error(`a user with the username ${username} already exists.`)
        }
        throw error
      })
    return user
  },

  async getUserById({
    id,
    select = ['id', 'username', 'created_at'],
  }){
    return await knex
      .select(select)
      .from('users')
      .where({ id })
      .first()
  },

  async getDIDDocument(){

  },

  async getUserByUsername({
    username,
    select = ['id', 'username', 'created_at'],
  }){
    const record = await knex
      .select(select)
      .from('users')
      .where({ username })
      .first()

    return record
  },

  async authenticateUser({username, password}){
    const record = await this.getUserByUsername(username, ['id', 'password_hash'])
    if (!record) return
    const match = await bcrypt.compare(password, record.password_hash);
    if (match) return await this.getUserById({ id: record.id })
  }
}


export default db



