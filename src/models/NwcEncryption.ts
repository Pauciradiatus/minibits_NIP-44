/**
 * NIP-47 encryption negotiation: which scheme a request uses, and what the info
 * event advertises so that clients pick NIP-44.
 *
 * Split out of NwcStore so the negotiation can be exercised without loading the
 * whole store (nostr, notifee, firebase), like NwcTransaction.
 */

export enum NwcEncryption {
    NIP44_V2 = 'nip44_v2',
    NIP04 = 'nip04',
}

/**
 * Preference order, as advertised in the info event. NIP-47 deprecates nip04 and
 * asks clients to pick nip44 whenever the wallet offers it; nip04 stays for the
 * clients written before the encryption tag existed.
 */
export const SUPPORTED_NWC_ENCRYPTIONS: NwcEncryption[] = [NwcEncryption.NIP44_V2, NwcEncryption.NIP04]

const ENCRYPTION_TAG = 'encryption'

/**
 * The scheme a request is encrypted with, or undefined for one this wallet does not
 * speak. A request without the tag is nip04: that is every client written before
 * NIP-47 added it, and what the spec says to assume.
 */
export const getRequestEncryption = (tags: string[][]): NwcEncryption | undefined => {
    const tag = tags.find(([name]) => name === ENCRYPTION_TAG)
    if (!tag) {
        return NwcEncryption.NIP04
    }

    const scheme = tag[1]?.trim()
    return SUPPORTED_NWC_ENCRYPTIONS.find(supported => supported === scheme)
}

/**
 * The scheme a response goes out in: the request's own. A request in a scheme the
 * wallet does not speak still gets its UNSUPPORTED_ENCRYPTION error, in nip04,
 * the one scheme every NWC client can read.
 */
export const getResponseEncryption = (requestTags: string[][]): NwcEncryption =>
    getRequestEncryption(requestTags) ?? NwcEncryption.NIP04

export const getInfoEventTags = (): string[][] => [
    [ENCRYPTION_TAG, SUPPORTED_NWC_ENCRYPTIONS.join(' ')],
]

/**
 * Whether the published info event already says what this wallet would publish now.
 * One without the encryption tag tells clients the wallet speaks nip04 only, which
 * is what every connection created before NIP-44 support has on the relays.
 */
export const isInfoEventCurrent = (
    event: {content: string, tags: string[][]} | null | undefined,
    supportedMethods: string[],
): boolean => {
    if (!event) {
        return false
    }

    const encryption = event.tags.find(([name]) => name === ENCRYPTION_TAG)?.[1]

    return event.content === supportedMethods.join(' ')
        && encryption === SUPPORTED_NWC_ENCRYPTIONS.join(' ')
}
