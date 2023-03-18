import Knex from 'knex'
import bcrypt from 'bcrypt'

import {
  generateSigningKeyPair,
  generateEncryptingKeyPair,
  keyPairToPrivateJWK,
  keyPairFromJWK,
  publicKeyToBase58,
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
  async getOrCreateAppCryptoKeyPairs(){
    const keys = await knex.select('*').from('crypto_keys').whereNull('user_id')
    const signingKeyPairs = []
    const encryptingKeyPairs = []
    for (const key of keys){
      const keyPair = await keyPairFromJWK(JSON.parse(key.jwk))
      if (key.type === 'signing') signingKeyPairs.push(keyPair)
      if (key.type === 'encrypting') encryptingKeyPairs.push(keyPair)
    }
    const keyPairsToInsert = []
    if (signingKeyPairs.length < 1){
      const keyPair = await generateSigningKeyPair()
      signingKeyPairs.push(keyPair)
      keyPairsToInsert.push(['signing', keyPair])
    }
    if (encryptingKeyPairs.length < 1){
      const keyPair = await generateEncryptingKeyPair()
      encryptingKeyPairs.push(keyPair)
      keyPairsToInsert.push(['encrypting', keyPair])
    }

    if (keyPairsToInsert.length > 0){
      console.log('CREATING APP CRYPTO KEYS')
      await knex('crypto_keys').insert(
        await Promise.all(
          keyPairsToInsert.map(async ([type, keyPair]) => {
            const jwk = await keyPairToPrivateJWK(keyPair)
            return {
              // user_id: null,
              public_key: jwk.x,
              jwk: JSON.stringify(jwk),
              type,
            }
          })
        )
      )

    }

    return { signingKeyPairs, encryptingKeyPairs }
  },
  async getAllSessions(){
    return await knex.select('*').from('sessions')
  },
  async getAllUsers(){
    return await knex.select('*').from('users')
  },
  async createUser({ username, password, name, avatarURL }){
    const passwordHash = await bcrypt.hash(password, 10)
    const signingKeyPair = await generateSigningKeyPair()
    const publicKeyBase58 = publicKeyToBase58(signingKeyPair.publicKey)
    const signingJWK = await keyPairToPrivateJWK(signingKeyPair)
    const encryptingJWK = await keyPairToPrivateJWK(await generateEncryptingKeyPair())

    await knex.transaction(async knex => {
      const [user] = await knex
        .insert({
          created_at: new Date,
          username,
          name,
          avatar_url: avatarURL,
          password_hash: passwordHash,
          public_key: publicKeyBase58,
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

      await knex()
        .insert([
          {
            user_id: user.id,
            public_key: signingJWK.x,
            jwk: signingJWK,
            type: 'signing',
          },
          {
            user_id: user.id,
            public_key: encryptingJWK.x,
            jwk: encryptingJWK,
            type: 'encrypting',
          },
        ])
        .into('crypto_keys')

      return await this.getUserById({ id: user.id })
    })
  },

  async findUser({
    id,
    username,
    select = [
      'id', 'username', 'name', 'created_at', 'avatar_url',
      'signing_jwk', 'encrypting_jwk'
    ],
  }){
    const where = {}
    if (id) where.id = id
    if (username) where.username = username
    return await knex
      .select(select)
      .from('users')
      .where(where)
      .first()
      .then(userRecordToUser)
  },

  async getUserById({ id, select }){
    return await this.findUser({ id, select })
  },

  async getUserByUsername({ username, select }){
    return await this.findUser({ username, select })
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