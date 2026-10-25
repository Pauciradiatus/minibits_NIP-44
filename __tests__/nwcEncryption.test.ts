/**
 * NIP-47 encryption negotiation, end to end through a real NWC connection.
 *
 * Before this, every request was decrypted as nip04 whatever its encryption tag
 * said, so a client speaking nip44 got a decryption error and no answer at all;
 * and the info event carried no encryption tag, which tells every spec-following
 * client the wallet speaks nip04 only. These pin both halves: the request decides
 * the scheme of its response, and the info event advertises nip44 first.
 *
 * @jest-environment node
 */
jest.mock('../src/services/logService', () => ({
    log: {debug: jest.fn(), error: jest.fn(), info: jest.fn(), trace: jest.fn(), warn: jest.fn()},
}))
jest.mock('../src/services/minibitsService', () => ({MinibitsClient: {}}))
jest.mock('../src/services/walletService', () => ({WalletTask: {}}))
// The services barrel loads notifee, firebase and the database. NwcStore needs
// only NostrClient from it: the real encryption, with the relays stubbed out.
jest.mock('../src/services', () => {
    const {NostrClient} = jest.requireActual('../src/services/nostrService')
    return {
        NostrClient: {
            ...NostrClient,
            getMinibitsRelays: () => ['wss://relay.test'],
            getEvent: jest.fn(),
            publish: jest.fn(),
        },
        KeyChain: {},
        Database: {},
        SyncQueue: {},
        HANDLE_NWC_REQUEST_TASK: 'handleNwcRequestTask',
    }
})
jest.mock('../src/services/notificationService', () => ({
    NotificationService: {createLocalNotification: jest.fn()},
}))
jest.mock('../src/services/lightning/lightningUtils', () => ({LightningUtils: {}}))
jest.mock('../src/services/wallet/transferTask', () => ({transferTask: jest.fn()}))
jest.mock('../src/services/wallet/topupTask', () => ({topupTask: jest.fn()}))

import {types} from 'mobx-state-tree'
import {generateSecretKey, getPublicKey} from 'nostr-tools/pure'
import {bytesToHex} from '@noble/hashes/utils.js'
import {NWCWalletInfo, NWCWalletRequest, NWCWalletResponse} from 'nostr-tools/kinds'
import {NostrClient} from '../src/services'
import {NwcConnectionModel, NwcStoreModel} from '../src/models/NwcStore'
import {
    getInfoEventTags,
    getRequestEncryption,
    isInfoEventCurrent,
    NwcEncryption,
} from '../src/models/NwcEncryption'

const publish = NostrClient.publish as jest.Mock
const getEvent = NostrClient.getEvent as jest.Mock

const newKeyPair = () => {
    const secretKey = generateSecretKey()
    return {privateKey: bytesToHex(secretKey), publicKey: getPublicKey(secretKey)}
}

const wallet = newKeyPair()
const client = newKeyPair()

/** Just enough of the root store for NwcStore: the wallet's nostr keys and pubkey. */
const TestRootModel = types
    .model('TestRoot', {nwcStore: NwcStoreModel})
    .volatile(() => ({
        walletStore: {getCachedWalletKeys: async () => ({NOSTR: wallet})},
        walletProfileStore: {pubkey: wallet.publicKey, lud16: 'test@minibits.cash'},
    }))

const createStore = () => TestRootModel.create({
    nwcStore: {
        nwcConnections: [NwcConnectionModel.create({
            name: 'test',
            connectionSecret: client.privateKey,
            connectionPubkey: client.publicKey,
        })],
    },
}).nwcStore

const createConnection = () => createStore().nwcConnections[0]

/** A request as an NWC client builds it: encrypted to the wallet, signed by the connection key. */
const buildRequest = async (encryption: NwcEncryption, tags: string[][]) => {
    const content = JSON.stringify({method: 'get_info', params: {}})
    const encrypted = encryption === NwcEncryption.NIP44_V2
        ? await NostrClient.encryptNip44(wallet.publicKey, content, client)
        : await NostrClient.encryptNip04(wallet.publicKey, content, client)

    return {
        id: 'a'.repeat(64),
        pubkey: client.publicKey,
        kind: NWCWalletRequest,
        created_at: Math.floor(Date.now() / 1000),
        tags: [['p', wallet.publicKey], ...tags],
        content: encrypted,
        sig: 'b'.repeat(128),
    }
}

/** The one response the wallet published, as the client reads it. */
const readResponse = async (encryption: NwcEncryption) => {
    expect(publish).toHaveBeenCalledTimes(1)
    const [event] = publish.mock.calls[0]
    expect(event.kind).toBe(NWCWalletResponse)

    const content = encryption === NwcEncryption.NIP44_V2
        ? await NostrClient.decryptNip44(wallet.publicKey, event.content, client)
        : await NostrClient.decryptNip04(wallet.publicKey, event.content, client)

    return {event, response: JSON.parse(content)}
}

beforeEach(() => {
    publish.mockReset().mockResolvedValue(undefined)
    getEvent.mockReset()
})

describe('NWC request handling', () => {
    it('answers a nip44 request in nip44', async () => {
        const request = await buildRequest(NwcEncryption.NIP44_V2, [['encryption', 'nip44_v2']])

        await createConnection().handleNwcRequestTask(request)

        const {event, response} = await readResponse(NwcEncryption.NIP44_V2)
        expect(event.content).not.toContain('?iv=')
        expect(event.tags).toEqual([['p', client.publicKey], ['e', request.id]])
        expect(response.result_type).toBe('get_info')
        expect(response.result.pubkey).toBe(wallet.publicKey)
    })

    it('answers a request without the encryption tag in nip04, as before', async () => {
        const request = await buildRequest(NwcEncryption.NIP04, [])

        await createConnection().handleNwcRequestTask(request)

        const {event, response} = await readResponse(NwcEncryption.NIP04)
        expect(event.content).toContain('?iv=')
        expect(response.result_type).toBe('get_info')
    })

    it('answers a request explicitly tagged nip04 in nip04', async () => {
        const request = await buildRequest(NwcEncryption.NIP04, [['encryption', 'nip04']])

        await createConnection().handleNwcRequestTask(request)

        const {response} = await readResponse(NwcEncryption.NIP04)
        expect(response.result_type).toBe('get_info')
    })

    it('answers an unknown scheme with UNSUPPORTED_ENCRYPTION, in nip04', async () => {
        const request = await buildRequest(NwcEncryption.NIP04, [['encryption', 'nip99']])

        await createConnection().handleNwcRequestTask(request)

        const {response} = await readResponse(NwcEncryption.NIP04)
        expect(response.result_type).toBe('')
        expect(response.error.code).toBe('UNSUPPORTED_ENCRYPTION')
        expect(response.error.message).toContain('nip44_v2')
    })
})

describe('ensureInfoEvent', () => {
    const methods = () => createStore().supportedMethods as string[]

    it('publishes when the relays have no info event yet', async () => {
        getEvent.mockResolvedValue(null)

        await createStore().ensureInfoEvent()

        expect(publish).toHaveBeenCalledTimes(1)
        const [event] = publish.mock.calls[0]
        expect(event.kind).toBe(NWCWalletInfo)
        expect(event.pubkey).toBe(wallet.publicKey)
        expect(event.tags).toEqual([['encryption', 'nip44_v2 nip04']])
        expect(event.content).toBe(methods().join(' '))
    })

    it('republishes the info event of a connection created before NIP-44 support', async () => {
        getEvent.mockResolvedValue({kind: NWCWalletInfo, content: methods().join(' '), tags: []})

        await createStore().ensureInfoEvent()

        expect(publish).toHaveBeenCalledTimes(1)
        expect(publish.mock.calls[0][0].tags).toEqual(getInfoEventTags())
    })

    it('leaves a current info event alone', async () => {
        getEvent.mockResolvedValue({kind: NWCWalletInfo, content: methods().join(' '), tags: getInfoEventTags()})

        await createStore().ensureInfoEvent()

        expect(publish).not.toHaveBeenCalled()
    })

    it('does not throw when the relays are unreachable', async () => {
        getEvent.mockRejectedValue(new Error('no relay'))

        await expect(createStore().ensureInfoEvent()).resolves.toBeUndefined()
        expect(publish).not.toHaveBeenCalled()
    })
})

describe('getRequestEncryption', () => {
    it.each([
        [[], NwcEncryption.NIP04],
        [[['encryption', 'nip04']], NwcEncryption.NIP04],
        [[['encryption', 'nip44_v2']], NwcEncryption.NIP44_V2],
        [[['encryption', ' nip44_v2 ']], NwcEncryption.NIP44_V2],
        [[['encryption', 'nip44']], undefined],
        [[['encryption']], undefined],
    ])('reads %j as %s', (tags, expected) => {
        expect(getRequestEncryption(tags as string[][])).toBe(expected)
    })
})

describe('isInfoEventCurrent', () => {
    const methods = ['pay_invoice', 'get_info']

    it('wants a republish when the methods changed', () => {
        expect(isInfoEventCurrent({content: 'pay_invoice', tags: getInfoEventTags()}, methods)).toBe(false)
    })

    it('accepts the event this wallet would publish now', () => {
        expect(isInfoEventCurrent({content: methods.join(' '), tags: getInfoEventTags()}, methods)).toBe(true)
    })
})
