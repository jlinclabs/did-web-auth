/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
export async function up(knex) {
  await knex.schema.createTable('users', function (table) {
    table.increments('id')
    table.timestamps(true, true)
    table.string('did').notNullable().unique()
    table.string('username').notNullable().unique()
    table.string('password_hash').nullable()
    table.string('profile_url').nullable()
  })

  await knex.schema.createTable('crypto_keys', function (table) {
    table.integer('user_id').unsigned().nullable()
    table.foreign('user_id').references('users.id')
    table.string('public_key').primary(), // base64url
    table.json('jwk').notNullable()
    table.enum('type', ['signing', 'encrypting']).notNullable()
    table.timestamps(true, false)
  })

  await knex.schema.createTable('sessions', function (table) {
    table.string('sid').primary()
    table.json('sess').notNullable()
    table.dateTime('expired').notNullable().index()
    table.timestamps(true, true)
  })

  await knex.schema.createTable('profiles', function (table) {
    table.integer('user_id').primary()
    table.foreign('user_id').references('users.id')
    table.string('name').nullable()
    table.string('avatar_url').nullable()
    table.string('bio').nullable()
  })
}

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
export async function down(knex) {
  await knex.schema.dropTableIfExists('crypto_keys')
}
