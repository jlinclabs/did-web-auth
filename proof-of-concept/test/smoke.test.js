import test from 'brittle'
import { startAppInstance } from './helpers.js'

test('smoke', async t => {
  const [app1, app2] = await Promise.all([
    startAppInstance(t),
    startAppInstance(t),
  ])
  t.is(typeof Date.now(), 'number')
  t.not(typeof Date.now(), 'string')

  console.log({ app1, app2 })

})
