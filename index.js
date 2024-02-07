#!/usr/bin/env node
const { app } = require('./app')

const PORT = process.env.MOCKPASS_PORT || process.env.PORT || 5156

app.listen(PORT, (err) =>
  err
    ? console.error('Unable to start MockPass', err)
    : console.warn(`MockPass listening on ${PORT}`),
)
