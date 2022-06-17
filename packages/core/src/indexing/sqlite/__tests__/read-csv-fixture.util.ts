import { IndexStreamArgs } from '../../database-index-api.js'
import fs from 'node:fs'
import csv from 'csv-parser'
import { StreamID } from '@ceramicnetwork/streamid'

const MODEL_ID = 'kjzl6cwe1jw145m7jxh4jpa6iw1ps3jcjordpo81e0w04krcpz8knxvg5ygiabd'
const MODEL = StreamID.fromString(MODEL_ID)

export function readCsvFixture(filepath: URL) {
  type CsvFixture = IndexStreamArgs & { createdAt?: Date }
  return new Promise<Array<CsvFixture>>((resolve, reject) => {
    const result = new Array<CsvFixture>()
    const csvReader = csv({
      separator: ';',
      mapHeaders: ({ header }) => (header ? header.replace(/\s+/g, '') : null),
    })
    fs.createReadStream(filepath)
      .pipe(csvReader)
      .on('data', (row) => {
        result.push({
          model: MODEL,
          streamID: StreamID.fromString(row.stream_id),
          controller: row.controller,
          lastAnchor: row.last_anchored_at
            ? new Date(Number(row.last_anchored_at) * 1000)
            : undefined,
          createdAt: row.created_at ? new Date(Number(row.created_at) * 1000) : undefined,
        })
      })
      .on('error', (error) => reject(error))
      .on('end', () => {
        resolve(result)
      })
  })
}
