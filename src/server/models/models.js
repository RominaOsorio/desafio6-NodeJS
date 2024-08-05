import bcrypt from 'bcrypt'
import db from '../../database/config.js'

export const getUser = async (email) => {
  try {
    const query = 'SELECT email, rol, lenguage FROM usuarios WHERE email = $1;'
    const values = [email]
    const { rows } = await db(query, values)
    return rows
  } catch (error) {
    const newError = { status: false, message: error }
    throw newError
  }
}

export const register = async ({ email, password, rol, lenguage }) => {
  const query = 'INSERT INTO usuarios (id, email, password, rol, lenguage) VALUES (DEFAULT, $1, $2, $3, $4) RETURNING *;'
  const encriptada = bcrypt.hashSync(password)
  const values = [email, encriptada, rol, lenguage]
  const { rowCount } = await db(query, values)
  if (!rowCount) {
    const newError = { status: false, message: 'No se pudo crear el registro' }
    throw newError
  }
}

export const verify = async (email, password) => {
  const query = 'SELECT * FROM usuarios WHERE email = $1;'
  const values = [email]
  const { rows: [usuario], rowCount } = await db(query, values)
  const encriptada = usuario.password
  const passwordCorrecta = await bcrypt.compare(password, encriptada)
  if (!passwordCorrecta || !rowCount) {
    const newError = { status: false, message: 'Datos incorrectos' }
    throw newError
  }
}
