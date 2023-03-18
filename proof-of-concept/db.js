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
  log: {
    warn(message) {
      console.warn('KNEX Warning:', message);
    },
    error(message) {
      console.error('KNEX Error:', message);
    },
    deprecate(message) {
      console.log('KNEX Deprecation warning:', message);
    },
    debug(message) {
      console.log('KNEX Debug:', message);
    }
  }
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
    username, password, did, profileURL, profile
  }){
    console.log('createUser', {username, password, did, profileURL, profile})
    const signingKeyPair = await generateSigningKeyPair()
    const signingJWK = await keyPairToPrivateJWK(signingKeyPair)
    const encryptingJWK = await keyPairToPrivateJWK(await generateEncryptingKeyPair())
    const usersRecord = { username, did }
    if (password) usersRecord.password_hash = await bcrypt.hash(password, 10)
    if (profileURL) usersRecord.profile_url = profileURL
    let profileRecord
    if (profile){
      profileRecord = {}
      if (profile.name) profileRecord.name = profile.name
      if (profile.avatarURL) profileRecord.avatar_url = profile.avatarURL
      if (profile.bio) profileRecord.bio = profile.bio
    }
    const userId = await this.knex.transaction(async knex => {

      const [{id: userId}] = await knex('users').insert(usersRecord).returning('id')
      console.log('created user', userId)
      if (profileRecord){
        profileRecord.user_id = userId
        await knex('profiles').insert(profileRecord)
        console.log('created users profile record', userId)
      }

      await knex('crypto_keys').insert([
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
    select = [ 'id', 'username', 'created_at', 'profile_url' ],
    includePasswordHash = false,
    includeCryptoKeys = true,
  }){
    if (includePasswordHash) select.push('password_hash')
    const where = {}
    if (id) where.id = id
    if (username) where.username = username
    const user = await this.knex('users').select(select).where(where).first()
    if (!user) return

    let profile = await this.knex('profiles')
      .select(['name', 'avatar_url', 'bio'])
      .where({ user_id: user.id }).first()
    console.log({ profile })
    if (!profile && user.profile_url) {
      profile = await fetchProfile(user.profile_url)
      console.log('fetched remote profile', {userId: id, profile})
    }
    if (profile) {
      user.name = profile.name
      user.avatar_url = profile.avatar_url
      user.bio = profile.bio
    }


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


async function deserializeKeyPairs(user, prop){
  user[prop] &&= await keyPairFromJWK(JSON.parse(user[prop]))
}