import test from 'brittle'
import { praseDIDWeb } from '../dids.js'


test('praseDIDWeb', async t => {
  t.alike(
    praseDIDWeb('did:web:example.com'),
    {
      host: 'example.com',
    }
  )
  t.alike(
    praseDIDWeb('did:web:example.com:u:jared'),
    {
      host: 'example.com',
      path: ':u:jared',
      username: 'jared'
    }
  )
})