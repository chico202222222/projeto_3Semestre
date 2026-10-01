import { validateCreateUser } from './createUserSchema.js'

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
    return
  }

  event.preventDefault()

  const messages = []
  for (const issue of result.error.issues) {
    messages.push(issue.message)
  }

  errorMessage.textContent = messages.join(' ')
})
