/*
 * Database
 *
 *
 */
import Knex from 'knex'

const knex = Knex({
  client: 'better-sqlite3',
  connection: {
    filename: process.env.DATABASE_FILE
  }
})
export { knex }

const db = {
  async createUser(){

  },

  async getDIDDocument(){

  },
}
export default db



