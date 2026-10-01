function convertToBase64(bytes) {
  let text = ''
  for (const byte of bytes) text += String.fromCharCode(byte)
  return btoa(text) // hashing
}

function convertPublicKey(pem) {
  const keyText = pem.replace('-----BEGIN PUBLIC KEY-----', '') // BASICA CHAVE RSA
    .replace('-----END PUBLIC KEY-----', '')
    .replace(/\s/g, '')
  const keyBytes = atob(keyText)
  const keyArray = new Uint8Array(keyBytes.length)

  for (let i = 0; i < keyBytes.length; i++) {
    keyArray[i] = keyBytes.charCodeAt(i)
  }

  return keyArray
}

export async function encryptAndSubmit(form) {
  const errorMessage = form.querySelector('#error')
  const button = form.querySelector('button[type="submit"]')
  button.disabled = true

  try {
    const response = await fetch('/crypto/public-key')
    const keyData = await response.json()
    const rsaKey = await crypto.subtle.importKey(
      'spki',
      convertPublicKey(keyData.public_key),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt'],
    )

    const aesKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt'],
    )
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const formData = new FormData(form)
    const values = {}

    for (const [name, value] of formData.entries()) {
      values[name] = value
    }

    const encryptedData = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      new TextEncoder().encode(JSON.stringify(values)),
    )
    const rawAesKey = await crypto.subtle.exportKey('raw', aesKey)
    const encryptedKey = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      rsaKey,
      rawAesKey,
    )

    for (const input of form.querySelectorAll('input[name]')) {
      input.removeAttribute('name')
    }

    const encryptedFields = {
      encrypted_key: convertToBase64(new Uint8Array(encryptedKey)),
      iv: convertToBase64(iv),
      encrypted_data: convertToBase64(new Uint8Array(encryptedData)),
    }

    for (const name in encryptedFields) {
      const input = document.createElement('input')
      input.type = 'hidden'
      input.name = name
      input.value = encryptedFields[name]
      form.appendChild(input)
    }

    form.submit()
  } catch (error) {
    errorMessage.textContent = 'Não foi possível proteger os dados. Tente novamente.'
    button.disabled = false
  }
}

const loginForm = document.getElementById('loginForm')
if (loginForm) {
  loginForm.addEventListener('submit', function (event) {
    event.preventDefault()
    encryptAndSubmit(loginForm)
  })
}
