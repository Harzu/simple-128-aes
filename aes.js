const utils = require('./utils')

class AES {
  constructor(nb = 4, nk = 4, nr = 10) {
    this.Nb = nb // columns count
    this.Nk = nk // key length
    this.Nr = nr // round length
  }

  _createState(block) {
    const state = [ [], [], [], [] ]
    for (let col = 0; col < this.Nb; col++) {
      for (let row = 0; row < 4; row++) {
        state[row][col] = block[row + (4 * col)]
      }
    }

    return state
  }

  _generateOutput(state) {
    const output = []
    for (let col = 0; col < this.Nb; col++) {
      for (let row = 0; row < 4; row++) {
        output[row + (4 * col)] = state[row][col]
      }
    }

    return output
  }

  _rotateWord(temp) {
    const moveElem = temp[0]
    temp.shift()
    temp.push(moveElem)
  }

  _subWord(temp) {
    for (let i = 0; i < 4; i++) {
      temp[i] = utils.sBox[temp[i]]
    }
  }

  keyExpansion(key) {
    const storeLength = this.Nb * (this.Nr + 1)
    const keyStore = new Array(storeLength)

    // include init key store values from key
    for (let i = 0; i < this.Nk; i++) {
      const row = [ key[4 * i], key[(4 * i) + 1], key[(4 * i) + 2], key[(4 * i) + 3] ]
      keyStore[i] = row
    }

    for (let i = this.Nk; i < storeLength; i++) {
      const temp = new Array(4)
      keyStore[i] = new Array(4)

      // include to temp array values from old column
      for (let t = 0; t < 4; t++) {
        temp[t] = keyStore[i - 1][t]
      }

      if (i % this.Nk === 0) {
        this._rotateWord(temp)
        this._subWord(temp)

        for (let t = 0; t < 4; t++) {
          temp[t] ^= utils.rCon[i / this.Nk][t]
        }
      }

      for (let t = 0; t < 4; t++) {
        keyStore[i][t] = keyStore[i - this.Nk][t] ^ temp[t]
      }
    }

    return keyStore
  }

  addRoundKey(state, key_sh, round) {
    const roundKey_sh = (round === 0)
      ? key_sh.slice(0, 4)
      : key_sh.slice(this.Nb * round, (this.Nb * round) + 4)

    for (let col = 0; col < this.Nb; col++) {
      for (let row = 0; row < 4; row++) {
        state[row][col] ^= roundKey_sh[row][col]
      }
    }
  }

  mixColumns(state, inversion = false) {
    for (let column = 0; column < state.length; column++) {
      let s1, s2, s3, s4;
      if (!inversion) {
        s1 = utils.mul02(state[0][column]) ^ utils.mul03(state[1][column]) ^ state[2][column] ^ state[3][column]
        s2 = state[0][column] ^ utils.mul02(state[1][column]) ^ utils.mul03(state[2][column]) ^ state[3][column]
        s3 = state[0][column] ^ state[1][column] ^ utils.mul02(state[2][column]) ^ utils.mul03(state[3][column])
        s4 = utils.mul03(state[0][column]) ^ state[1][column] ^ state[2][column] ^ utils.mul02(state[3][column])
      } else {
        s1 = utils.mul0e(state[0][column]) ^ utils.mul0b(state[1][column]) ^ utils.mul0d(state[2][column]) ^ utils.mul09(state[3][column])
        s2 = utils.mul09(state[0][column]) ^ utils.mul0e(state[1][column]) ^ utils.mul0b(state[2][column]) ^ utils.mul0d(state[3][column])
        s3 = utils.mul0d(state[0][column]) ^ utils.mul09(state[1][column]) ^ utils.mul0e(state[2][column]) ^ utils.mul0b(state[3][column])
        s4 = utils.mul0b(state[0][column]) ^ utils.mul0d(state[1][column]) ^ utils.mul09(state[2][column]) ^ utils.mul0e(state[3][column])
      }

      state[0][column] = s1
      state[1][column] = s2
      state[2][column] = s3
      state[3][column] = s4
    }
  }

  subBytes(state, inversion = false) {
    const box = !inversion ? utils.sBox : utils.invSBox
    for (let i = 0; i < state.length; i++) {
      for (let j = 0; j < state.length; j++) {
        const row = Math.floor(state[i][j] / 16)
        const column = state[i][j] % 16

        state[i][j] = box[(16 * row) + column]
      }
    }

    return state
  }

  shiftRows(state, inversion = false) {
    return (inversion) ? this._shift_right(state) : this._shift_left(state)
  }

  _shift_left(state) {
    for (let i = 1; i < state.length; i++) {
      for (let count = 0; count < i; count++) {
        const moveElem = state[i][0]
        state[i].shift()
        state[i].push(moveElem)
      }
    }

    return state
  }

  _shift_right(state) {
    for (let i = 1; i < state.length; i++) {
      for (let count = 0; count < i; count++) {
        const lastElem = state[i][3]
        state[i].pop()
        state[i].unshift(lastElem)
      }
    }

    return state
  }


  encrypt(message, encryptKey) {
    message = String(message)
    encryptKey = String(encryptKey)

    const key = utils.generate16ByteBlocks(encryptKey)[0]
    const blocks = utils.generate16ByteBlocks(message)

    const result = []
    const keys_sh = this.keyExpansion(key)
    for (let block of blocks) {
      const state = this._createState(block)

      this.addRoundKey(state, keys_sh, 0)

      for (let i = 1; i < this.Nr; i++) {
        this.subBytes(state)
        this.shiftRows(state)
        this.mixColumns(state)
        this.addRoundKey(state, keys_sh, i)
      }

      this.subBytes(state)
      this.shiftRows(state)
      this.addRoundKey(state, keys_sh, this.Nr)

      result.push(this._generateOutput(state))
    }

    return result
  }

  decrypt(encrypt_bytes, decryptKey) {
    decryptKey = String(decryptKey)
    const key = utils.generate16ByteBlocks(decryptKey)[0]

    const result = []
    const keys_sh = this.keyExpansion(key)
    for (let block of encrypt_bytes) {
      const state = this._createState(block)

      this.addRoundKey(state, keys_sh, this.Nr)

      for (let i = this.Nr - 1; i >= 1; i--) {
        this.shiftRows(state, true)
        this.subBytes(state, true)
        this.addRoundKey(state, keys_sh, i)
        this.mixColumns(state, true)
      }

      this.shiftRows(state, true)
      this.subBytes(state, true)
      this.addRoundKey(state, keys_sh, 0)

      result.push(this._generateOutput(state))
    }

    return utils.parseBytesToString(result)
  }
}

module.exports = AES