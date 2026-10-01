import { validateCreateUser } from './createUserSchema.js'
import { encryptAndSubmit } from './basicSecurity.js'

const form = document.getElementById('registerForm')
const errorMessage = document.getElementById('error')

form.addEventListener('submit', function (event) {
  const formData = new FormData(form)

  const user = {
    name: formData.get('name'),
    email: formData.get('email'),
    password: formData.get('password'),
  }

  const result = validateCreateUser(user)

  if (result.success) {
    errorMessage.textContent = ''
    event.preventDefault()
    encryptAndSubmit(form)
    return
  }

  event.preventDefault()

  const messages = []
  for (const issue of result.error.issues) {
    messages.push(issue.message)
  }

  errorMessage.textContent = messages.join(' ')
})
