/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
export async function up(knex) {
  await knex.schema.createTable('sessions', function (table) {
    table.string('sid').primary()
    table.json('sess').notNullable()
    table.dateTime('expired').notNullable().index()
  })
  await knex.schema.createTable('users', function (table) {
    table.increments()
    table.timestamp('created_at').notNullable()
    table.string('username').notNullable().unique()
    table.string('password_hash').notNullable()
    table.json('public_key').notNullable()
    table.json('private_key').notNullable()
  })
}

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
export async function down(knex) {
  await knex.schema.dropTableIfExists('crypto_keys')
}
