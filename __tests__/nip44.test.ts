/**
 * NIP-44 v2 against the official test vectors (paulmillr/nip44, nip44.vectors.json).
 *
 * NWC requests and responses are encrypted with these helpers, so a wrong
 * conversation key or a payload another implementation cannot read means every
 * NIP-44 client gets no answer. The vectors pin the helpers to the spec, and with
 * it the nostr-tools version underneath them.
 *
 * @jest-environment node
 */
jest.mock('../src/services/logService', () => ({
    log: {debug: jest.fn(), error: jest.fn(), info: jest.fn(), trace: jest.fn(), warn: jest.fn()},
}))
// nostrService reaches the whole store (notifee, firebase) through these two. The
// encryption helpers use neither.
jest.mock('../src/services/minibitsService', () => ({MinibitsClient: {}}))
jest.mock('../src/services/walletService', () => ({WalletTask: {}}))

import {getPublicKey} from 'nostr-tools/pure'
import {decrypt as decryptV2} from 'nostr-tools/nip44'
import {bytesToHex, hexToBytes} from '@noble/hashes/utils.js'
import {NostrClient} from '../src/services/nostrService'
import vectors from './fixtures/nip44.vectors.json'

const {valid, invalid} = vectors.v2

const keyPair = (privateKey: string) => ({
    privateKey,
    publicKey: getPublicKey(hexToBytes(privateKey)),
})

describe('getNip44ConversationKey', () => {
    it.each(valid.get_conversation_key)('derives the vector key for $pub2', ({sec1, pub2, conversation_key}) => {
        expect(bytesToHex(NostrClient.getNip44ConversationKey(sec1, pub2))).toBe(conversation_key)
    })

    it.each(invalid.get_conversation_key)('rejects: $note', ({sec1, pub2}) => {
        expect(() => NostrClient.getNip44ConversationKey(sec1, pub2)).toThrow()
    })

    it('is symmetric, so both sides of a connection derive the same key', () => {
        const {sec1, sec2} = valid.encrypt_decrypt[0]
        const a = keyPair(sec1)
        const b = keyPair(sec2)

        expect(NostrClient.getNip44ConversationKey(a.privateKey, b.publicKey))
            .toEqual(NostrClient.getNip44ConversationKey(b.privateKey, a.publicKey))
    })
})

describe('decryptNip44', () => {
    it.each(valid.encrypt_decrypt)('reads the vector payload for "$plaintext"', async ({sec1, sec2, payload, plaintext}) => {
        const sender = keyPair(sec1)

        await expect(NostrClient.decryptNip44(sender.publicKey, payload, keyPair(sec2))).resolves.toBe(plaintext)
    })

    // These vectors carry only a conversation key, not the key pair behind it, so
    // they go to the library directly: what matters is that a tampered or malformed
    // payload throws instead of yielding a plaintext.
    it.each(invalid.decrypt)('rejects: $note', ({conversation_key, payload}) => {
        expect(() => decryptV2(payload, hexToBytes(conversation_key))).toThrow()
    })
})

describe('encryptNip44', () => {
    it.each(valid.encrypt_decrypt)('round-trips "$plaintext" to the other side', async ({sec1, sec2, plaintext}) => {
        const sender = keyPair(sec1)
        const receiver = keyPair(sec2)

        const payload = await NostrClient.encryptNip44(receiver.publicKey, plaintext, sender)

        await expect(NostrClient.decryptNip44(sender.publicKey, payload, receiver)).resolves.toBe(plaintext)
    })

    it('uses a fresh nonce, so the same message never encrypts the same way twice', async () => {
        const {sec1, sec2} = valid.encrypt_decrypt[0]
        const receiver = keyPair(sec2)

        const first = await NostrClient.encryptNip44(receiver.publicKey, 'pay_invoice', keyPair(sec1))
        const second = await NostrClient.encryptNip44(receiver.publicKey, 'pay_invoice', keyPair(sec1))

        expect(first).not.toBe(second)
    })

    it('produces a v2 payload, not the NIP-04 "?iv=" format', async () => {
        const {sec1, sec2} = valid.encrypt_decrypt[0]

        const payload = await NostrClient.encryptNip44(keyPair(sec2).publicKey, 'hello', keyPair(sec1))

        expect(payload).not.toContain('?iv=')
        expect(Buffer.from(payload, 'base64')[0]).toBe(2)
    })
})
