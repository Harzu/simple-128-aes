const AES = require('./aes')
const { expect } = require('chai')

const aes = new AES
describe('description', () => {
  it('encrypt', () => {
    // Arrange
    const message = 'hello world'
    const password = 'wid32145ddI'
    // Act
    const encrypt_bytes = aes.encrypt(message, password)
    // Assert
    expect(encrypt_bytes).to.be.a('array')
  })

  it('decrypt', () => {
    // Arrange
    const message = 'hello world'
    const password = 'wid32145ddI'
    // Act
    const encrypt_bytes = aes.encrypt(message, password)
    const decrypt_message = aes.decrypt(encrypt_bytes, password)
    // Assert
    expect(decrypt_message).to.be.a('string')
    expect(decrypt_message).to.be.equal(message)
  })
})