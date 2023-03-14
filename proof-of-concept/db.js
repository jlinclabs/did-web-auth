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

const ID = {
  async createUser(){

  },

  async getDIDDocument(){

  },
}
export { ID }



