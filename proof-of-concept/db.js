/*
 * Database
 *
 *
 */
import Knex from 'knex'

const knex = Knex({
  client: 'better-sqlite3',
  connection: {
    filename: process.env.DATABASE_FILE || ':memory:'
  },
  asyncStackTraces: true,
})
export { knex }

const ready = (async () => {
  await knex.migrate.latest()
})()


const db = {
  ready,

  async createUser({ username, password }){
    await this.ready
    const record = await knex
      .insert({

      })
      .into('users')

    console.log({ record })
    return record
  },

  async getDIDDocument(){
    await this.ready

  },

  async authenticateUser(){
    await this.ready

  }
}


export default db



