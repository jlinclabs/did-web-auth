/*
 * Database
 *
 *
 */
import Knex from 'knex'
import bcrypt from 'bcrypt'

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

    console.log({ user })
    return user
  },

  async getUserById(userId){
    return await knex
      .select(['id', 'username', 'created_at'])
      .from('users')
      .where({ id: userId })
      .first()
  },

  async getDIDDocument(){

  },

  async authenticateUser({username, password}){
    const record = await knex
      .select(['id', 'password_hash'])
      .from('users')
      .where({ username })
      .first()

    if (!record) return
    const match = await bcrypt.compare(password, record.password_hash);
    if (match) return await this.getUserById(record.id)
  }
}


export default db



