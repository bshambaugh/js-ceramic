import { EventEmitter } from 'events';
import CID from 'cids';
import cloneDeep from 'lodash.clonedeep';
import dagCBOR from 'ipld-dag-cbor';
import * as multihashes from 'multihashes';
import * as sha256 from '@stablelib/sha256';

import type { Document } from './document';
import { DoctypeUtils, IpfsApi, UnreachableCaseError } from '@ceramicnetwork/common';
import DocID from '@ceramicnetwork/docid';
import { DiagnosticsLogger, ServiceLogger } from '@ceramicnetwork/logger';
import { Repository } from './repository';
import {
  deserialize,
  MsgType,
  PubsubMessage,
  QueryMessage,
  ResponseMessage,
  serialize,
  UpdateMessage,
} from './pubsub-message';
import * as uint8arrays from 'uint8arrays';

const IPFS_GET_TIMEOUT = 60000 // 1 minute
const IPFS_MAX_RECORD_SIZE = 256000 // 256 KB
const IPFS_RESUBSCRIBE_INTERVAL_DELAY = 1000 * 15 // 15 sec
const TESTING = process.env.NODE_ENV == 'test'

/**
 * Describes one log message from the Dispatcher.
 */
interface LogMessage {
  peer: string;
  event: string;
  topic: string;
  from?: string;
  message?: Record<string, unknown>;
}

/**
 * Ceramic core Dispatcher used for handling messages from pub/sub topic.
 */
export class Dispatcher extends EventEmitter {
  private _peerId: string
  // Set of IDs for QUERY messages we have sent to the pub/sub topic but not yet heard a
  // corresponding RESPONSE message for. Maps the query ID to the primary DocID we were querying for.
  private readonly _outstandingQueryIds: Record<string, DocID>

  private _isRunning = true
  private _resubscribeInterval: any

  constructor (public _ipfs: IpfsApi, public topic: string, private readonly repository: Repository, private _logger: DiagnosticsLogger, private _pubsubLogger: ServiceLogger) {
    super()
    this._outstandingQueryIds = {}
  }

  /**
   * Initialize Dispatcher instance.
   */
  async init(): Promise<void> {
    this._peerId = this._peerId || (await this._ipfs.id()).id
    await this._subscribe(true)
    // If ipfs.libp2p is defined we have an internal ipfs node, this means that
    // we don't want to resubscribe since it will add multiple handlers.
    if (!TESTING && !this._ipfs.libp2p) {
      this._resubscribe()
    }
  }

  /**
   * Subscribes IPFS pubsub to `this.topic` and logs a `subscribe` event.
   *
   * Logs error if subscribe fails.
   */
  async _subscribe(force = false): Promise<void> {
    try {
      if (force || !(await this._ipfs.pubsub.ls()).includes(this.topic)) {
        await this._ipfs.pubsub.unsubscribe(this.topic, this.handleMessage)
        await this._ipfs.pubsub.subscribe(
          this.topic,
          this.handleMessage,
          // {timeout: IPFS_GET_TIMEOUT} // ipfs-core bug causes timeout option to throw https://github.com/ipfs/js-ipfs/issues/3472
        )
        this._pubsubLogger.log({peer: this._peerId, event: 'subscribed', topic: this.topic })
      }
    } catch (error) {
      if (error.message.includes('Already subscribed')) {
        this._logger.debug(error.message)
      } else if (error.message.includes('The user aborted a request')) {        // for some reason the first call to pubsub.subscribe throws this error
        this._subscribe(true)
      } else {
        this._logger.err(error.message)
      }
    }
  }

  /**
   * Periodically subscribes to IPFS pubsub topic.
   */
  _resubscribe(): void {
    this._resubscribeInterval = setInterval(async () => {
      await this._subscribe()
    }, IPFS_RESUBSCRIBE_INTERVAL_DELAY)
  }

  /**
   * Register one document.
   *
   * @param document - Document instance
   */
  async register (document: Document): Promise<void> {
    this.repository.add(document)

    // Build a QUERY message to send to the pub/sub topic to request the latest tip for this document
    const payload = this._buildQueryMessage(document)

    // Store the query id so we'll process the corresponding RESPONSE message when it comes in
    this._outstandingQueryIds[payload.id] = document.id.baseID

    this._ipfs.pubsub.publish(this.topic, JSON.stringify(payload))
    this._pubsubLogger.log({ peer: this._peerId, event: 'published', topic: this.topic, message: payload })
  }

  _buildQueryMessage(document: Document): Record<string, any> {
    const message = { typ: MsgType.QUERY, doc: document.id.baseID.toString() }

    // Add 'id' to message that is a hash of the message contents.
    const id = this._hashMessage(message)

    return {...message, id: id.toString()}
  }

  /**
   * Computes a sha-256 multihash of the input message canonicalized using dag-cbor
   * @param message
   */
  _hashMessage(message: any) : string {
    // DAG-CBOR encoding
    let id: Uint8Array = dagCBOR.util.serialize(message)

    // SHA-256 hash
    id = sha256.hash(id)

    // Multihash encoding
    const buf = Buffer.from(id)
    return uint8arrays.toString(multihashes.encode(buf, 'sha2-256'), 'base64url')
  }

  /**
   * Unregister document by ID.
   */
  unregister (docId: DocID): void {
    this.repository.delete(docId)
  }

  /**
   * Store Ceramic commit (genesis|signed|anchor).
   *
   * @param data - Ceramic commit data
   */
  async storeCommit (data: any): Promise<CID> {
    if (DoctypeUtils.isSignedCommitContainer(data)) {
      const { jws, linkedBlock } = data
      // put the JWS into the ipfs dag
      const cid = await this._ipfs.dag.put(jws, { format: 'dag-jose', hashAlg: 'sha2-256' })
      // put the payload into the ipfs dag
      await this._ipfs.block.put(linkedBlock, { cid: jws.link.toString() })
      await this._restrictRecordSize(jws.link.toString())
      await this._restrictRecordSize(cid)
      return cid
    }
    const cid = await this._ipfs.dag.put(data)
    await this._restrictRecordSize(cid)
    return cid
  }

  /**
   * Retrieves one Ceramic commit by CID, and enforces that the commit doesn't exceed the maximum
   * commit size. To load an IPLD path or a CID from IPFS that isn't a Ceramic commit,
   * use `retrieveFromIPFS`.
   *
   * @param cid - Commit CID
   */
  async retrieveCommit (cid: CID | string): Promise<any> {
    const record = await this._ipfs.dag.get(cid, { timeout: IPFS_GET_TIMEOUT })
    await this._restrictRecordSize(cid)
    return cloneDeep(record.value)
  }

  /**
   * Retrieves an object from the IPFS dag
   * @param cid
   * @param path - optional IPLD path to load, starting from the object represented by `cid`
   */
  async retrieveFromIPFS (cid: CID | string, path?: string): Promise<any> {
    const record = await this._ipfs.dag.get(cid, { timeout: IPFS_GET_TIMEOUT, path })
    return cloneDeep(record.value)
  }

  /**
   * Restricts record size to IPFS_MAX_RECORD_SIZE
   * @param cid - Record CID
   * @private
   */
  async _restrictRecordSize(cid: CID | string): Promise<void> {
    const stat = await this._ipfs.block.stat(cid, { timeout: IPFS_GET_TIMEOUT })
    if (stat.size > IPFS_MAX_RECORD_SIZE) {
      throw new Error(`${cid.toString()} record size ${stat.size} exceeds the maximum block size of ${IPFS_MAX_RECORD_SIZE}`)
    }
  }

  /**
   * Publishes Tip commit to pub/sub topic.
   *
   * @param docId  - Document ID
   * @param tip - Commit CID
   */
  async publishTip (docId: DocID, tip: CID): Promise<void> {
    await this.publish({
      typ: MsgType.UPDATE,
      doc: docId.baseID,
      tip: tip
    })
  }

  /**
   * Handles one message from the pub/sub topic.
   *
   * @param message - Message data
   */
  handleMessage = async (message: any): Promise<void> => {
    if (!this._isRunning) {
      this._logger.err('Dispatcher has been closed')
      return
    }

    if (message.from === this._peerId) {
      return
    }

    const parsed = deserialize(message.data, this._pubsubLogger, this._peerId, this.topic)

    switch (parsed.typ) {
      case MsgType.QUERY:
        return await this._handleQueryMessage(parsed)
      case MsgType.RESPONSE:
        return await this._handleResponseMessage(parsed)
      case MsgType.UPDATE:
        return await this._handleUpdateMessage(parsed)
      default:
        throw new UnreachableCaseError(parsed, "Unknown message type")
    }
  }

  /**
   * Handles an incoming Update message from the pub/sub topic.
   * @param message
   * @private
   */
  async _handleUpdateMessage(message: UpdateMessage): Promise<void> {
    if (this.repository.has(message.doc)) {
      const document = this.repository.get(message.doc)
      // TODO: add cache of cids here so that we don't emit event
      // multiple times if we get the message more than once.
      document.emit('update', new CID(message.tip))
    }

    // TODO: Handle 'anchorService' if present in message
  }

  /**
   * Handles an incoming Query message from the pub/sub topic.
   * @param message
   * @private
   */
  async _handleQueryMessage(message: QueryMessage): Promise<void> {
    // TODO Add validation the message adheres to the proper format.
    // TODO: Should we validate that the 'id' field is the correct hash of the rest of the message?
    if (this.repository.has(message.doc)) {
      const doc = this.repository.get(message.doc)

      // TODO: Handle 'paths' for multiquery support
      await this.publish({
        typ: MsgType.RESPONSE,
        id: message.id,
        tips: new Map().set(message.doc.toString(), doc.tip)
      })
    }
  }

  /**
   * Handles an incoming Response message from the pub/sub topic.
   * @param message
   * @private
   */
  async _handleResponseMessage(message: ResponseMessage): Promise<void> {
    const expectedDocID = this._outstandingQueryIds[message.id]
    // We're not expecting this RESPONSE message
    if (!expectedDocID) return;

    // TODO Iterate over all documents in 'tips' object and process the new tip for each
    const newTip = message.tips.get(expectedDocID.toString())
    if (!newTip) {
      throw new Error("Response to query with ID '" + message.id + "' is missing expected new tip for docID '" +
        expectedDocID + "'")
    }
    if (this.repository.has(expectedDocID)) {
      const document = this.repository.get(expectedDocID)
      document.emit('update', new CID(newTip))
    }
  }

  async publish(message: PubsubMessage): Promise<void> {
    if (!this._isRunning) {
      this._logger.err('Dispatcher has been closed')
      return
    }
    await this._ipfs.pubsub.publish(this.topic, serialize(message))
    this._pubsubLogger.log({ peer: this._peerId, event: 'published', topic: this.topic, message: message })
  }

  /**
   * Gracefully closes the Dispatcher.
   */
  async close(): Promise<void> {
    this._isRunning = false

    clearInterval(this._resubscribeInterval)

    await this.repository.close()

    await this._ipfs.pubsub.unsubscribe(this.topic)
  }
}
