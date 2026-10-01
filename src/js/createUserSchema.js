import { z } from 'zod'

const usernamePattern = /^[\p{L}\p{N}._-]+$/u // peguei da internet

const createUserSchema = z.object({
  name: z.string()
    .trim()
    .min(2, 'O nome precisa ter pelo menos 2 caracteres.')
    .max(100, 'O nome pode ter no máximo 100 caracteres.')
    .regex(usernamePattern, 'Use apenas letras, números, ponto, hífen ou sublinhado no nome.'),
  email: z.string()
    .trim()
    .max(254, 'O e-mail pode ter no máximo 254 caracteres.')
    .email('Informe um e-mail válido.'),
  password: z.string()
    .min(8, 'A senha precisa ter pelo menos 8 caracteres.')
    .max(128, 'A senha pode ter no máximo 128 caracteres.')
    .regex(/[a-z]/, 'Inclua uma letra minúscula na senha.')
    .regex(/[A-Z]/, 'Inclua uma letra maiúscula na senha.')
    .regex(/[0-9]/, 'Inclua um número na senha.'),
}).strict()

function validateCreateUser(data) {
  return createUserSchema.safeParse(data)
}

export { validateCreateUser }
