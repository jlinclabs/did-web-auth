import Knex from 'knex'
import bcrypt from 'bcrypt'

import {
  generateSigningKeyPair,
  generateEncryptingKeyPair,
  keyPairToPrivateJWK,
  keyPairFromJWK,
  publicKeyToBase58,
} from './crypto.js'
import { praseDIDWeb } from './dids.js';

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
    // pull the app keys from the database
    const keys = await this.knex.select('*').from('crypto_keys').whereNull('user_id')
    const signingKeyPairs = []
    const encryptingKeyPairs = []
    // convert them to keypair object
    for (const key of keys){
      const keyPair = await keyPairFromJWK(JSON.parse(key.jwk))
      if (key.type === 'signing') signingKeyPairs.push(keyPair)
      if (key.type === 'encrypting') encryptingKeyPairs.push(keyPair)
    }
    // if we have no signing key, create one
    const keyPairsToInsert = []
    if (signingKeyPairs.length < 1){
      const keyPair = await generateSigningKeyPair()
      signingKeyPairs.push(keyPair)
      keyPairsToInsert.push(['signing', await keyPairToPrivateJWK(keyPair)])
    }
    // if we have no encrypting key, create one
    if (encryptingKeyPairs.length < 1){
      const keyPair = await generateEncryptingKeyPair()
      encryptingKeyPairs.push(keyPair)
      keyPairsToInsert.push(['encrypting', await keyPairToPrivateJWK(keyPair)])
    }
    // if we made new keys, insert them
    if (keyPairsToInsert.length > 0){
      console.log('CREATING APP CRYPTO KEYS')
      await this.knex('crypto_keys').insert(
        keyPairsToInsert.map(async ([type, jwk]) => {
          return {
            public_key: jwk.x,
            jwk: JSON.stringify(jwk),
            type,
          }
        })
      )
    }
    return { signingKeyPairs, encryptingKeyPairs }
  },

  async createUser({
    username, password, did, profileURL, profile
  }){
    const signingKeyPair = await generateSigningKeyPair()
    const signingJWK = await keyPairToPrivateJWK(signingKeyPair)
    const encryptingKeyPair = await generateEncryptingKeyPair()
    const encryptingJWK = await keyPairToPrivateJWK(encryptingKeyPair)

    const usersRecord = { username, did }
    if (password) usersRecord.password_hash = await bcrypt.hash(password, 10)

    // if this is a remove user their profile lives at a URL
    if (profileURL) usersRecord.profile_url = profileURL
    let profileRecord

    // if this is a local user they have a profile record
    if (profile){
      profileRecord = {}
      if (profile.name) profileRecord.name = profile.name
      if (profile.avatarURL) profileRecord.avatar_url = profile.avatarURL
      if (profile.bio) profileRecord.bio = profile.bio
    }

    // start a sql transaction
    const userId = await this.knex.transaction(async knex => {
      const [{id: userId}] = await knex('users').insert(usersRecord).returning('id')

      if (profileRecord){
        profileRecord.user_id = userId
        await knex('profiles').insert(profileRecord)
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
      if (error.message.includes('UNIQUE constraint failed: users.did')){
        throw new Error(`a user with the did ${did} already exists.`)
      }
      throw error
    })
    return await this.getUserById(userId)
  },

  async findOrCreateRemoteUser({ did, profileURL }){
    const user = await this.getUserByDID(did)
    if (user) return user
    const didParts = praseDIDWeb(userDID)
    const username = `${didParts.username}@${didParts.host}`
    return await this.createUser({ did, username, profileURL })
  },

  async findUser({
    where = {},
    select = [ 'id', 'did', 'username', 'created_at', 'profile_url' ],
    includePasswordHash = false,
    includeCryptoKeys = true,
  }){
    if (includePasswordHash) select.push('password_hash')

    const user = await this.knex('users').select(select).where(where).first()
    if (!user) return

    let profile = await this.knex('profiles')
      .select(['name', 'avatar_url', 'bio'])
      .where({ user_id: user.id }).first()

    if (!profile && user.profile_url) {
      profile = await fetchProfile(user.profile_url)
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
    user.authentication_host = praseDIDWeb(user.did).host
    return user
  },

  async getUserById(id, opts){
    return await this.findUser({ ...opts, where: { id } })
  },

  async getUserByUsername(username, opts){
    return await this.findUser({ ...opts, where: { username } })
  },

  async getUserByDID(did, opts){
    return await this.findUser({ ...opts, where: { did } })
  },

  async authenticateUser({username, password}){
    const record = await this.getUserByUsername(username, {
      includePasswordHash: true,
    })
    if (!record) return
    const match = await bcrypt.compare(password, record.password_hash);
    if (match) return await this.getUserById(record.id)
  },

  async updateUserProfile({userId, name, avatarURL, bio}){
    const updates = {}
    if (name) updates.name = name
    if (avatarURL) updates.avatar_url = avatarURL
    if (bio) updates.bio = bio
    await knex('profiles').update(updates).where({ user_id: userId })
  },
}


export default db

async function fetchProfile(url){
  console.log('fetching remote profile', url)
  // TODO lower timeout
  // in a production app you'll probably want to cache these results
  const res = await fetch(url, {
    method: 'GET',
    headers: {
      accepts: 'application/json'
    }
  })
  const profile = res.json()
  // TODO json-ld checks
  return profile
}