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
  knex,
  async getOrCreateAppCryptoKeyPairs(){
    const keys = await this.knex.select('*').from('crypto_keys').whereNull('user_id')
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
      await this.knex('crypto_keys').insert(
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

  async createUser({
    username, password, did,
    profileURL, name, avatarURL, bio
  }){
    const signingKeyPair = await generateSigningKeyPair()
    const signingJWK = await keyPairToPrivateJWK(signingKeyPair)
    const encryptingJWK = await keyPairToPrivateJWK(await generateEncryptingKeyPair())
    const usersRecord = { username, did }
    if (password) usersRecord.password_hash = await bcrypt.hash(password, 10)
    let profileRecord
    if (profileURL){
      usersRecord.profile_url = profileURL
    }else{
      profileRecord = {}
      if (name) profileRecord.name = name
      if (avatarURL) profileRecord.avatar_url = avatarURL
      // if (bio) profileRecord.bio = bio
    }
    const userId = await this.knex.transaction(async knex => {
      const [{id: userId}] = await this.knex('users').insert(usersRecord).returning('id')
      if (profileRecord){
        await this.knex('profiles').insert(profileRecord).returning()
      }

      await this.knex('crypto_keys').insert([
        {
          user_id: userId,
          public_key: signingJWK.x,
          jwk: JSON.stringify(signingJWK),
          type: 'signing',
        },
        {
          user_id: userId,
          public_key: encryptingJWK.x,
          jwk: JSON.stringify(encryptingJWK),
          type: 'encrypting',
        },
      ])
      return userId
    }).catch(error => {
      if (error.message.includes('UNIQUE constraint failed: users.username')){
        throw new Error(`a user with the username ${username} already exists.`)
      }
      throw error
    })
    return await this.getUserById({ id: userId })
  },

  async findUser({
    id,
    username,
    select = [ 'id', 'username', 'created_at' ],
    includePasswordHash = false,
    includeCryptoKeys = true,
  }){
    if (includePasswordHash) select.push('password_hash')
    const where = {}
    if (id) where.id = id
    if (username) where.username = username
    const user = await this.knex
      .select(select)
      .from('users')
      .where(where)
      .leftJoin('profiles', 'users.id', 'profiles.user_id')
      .first()
      .then(userRecordToUser)

    if (!user) return
    if (includeCryptoKeys){
      const crypto_keys = await this.knex('crypto_keys').select('*').where({ user_id: user.id })
      for (const type of ['signing', 'encrypting']){
        const record = crypto_keys.find(k => k.type === type)
        const keyPair = await keyPairFromJWK(JSON.parse(record.jwk))
        user[`${type}_key_pair`] = keyPair
      }
    }
    console.log({ user })
    return user
  },

  async getUserById({ id, ...opts }){
    return await this.findUser({ id, ...opts })
  },

  async getUserByUsername({ username, ...opts }){
    return await this.findUser({ username, ...opts })
  },

  async authenticateUser({username, password}){
    const record = await this.getUserByUsername({
      username,
      includePasswordHash: true,
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