const express = require('express')
const fs = require('fs')
const path = require('path')
const assertions = require('../../assertions')

const CUSTOM_PERSONAS_FILE = path.resolve(__dirname, '../../../static/myinfo/custom-personas.json')

const router = express.Router()
router.use(express.json())

// Get custom personas
router.get('/personas', (req, res) => {
  try {
    if (fs.existsSync(CUSTOM_PERSONAS_FILE)) {
      const data = JSON.parse(fs.readFileSync(CUSTOM_PERSONAS_FILE, 'utf8'))
      res.json(data)
    } else {
      res.json({})
    }
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Create or update a persona
router.post('/personas', (req, res) => {
  try {
    const { nric, name, nationality, incomeLow, incomeHigh, schoolName, eduLevel, maritalStatus, noOfChildren, regAdd, mobileNo, email, password, dynamic_age, dob } = req.body

    if (!nric) {
      return res.status(400).json({ error: 'NRIC is required' })
    }

    // Load existing custom personas
    let customPersonas = {}
    if (fs.existsSync(CUSTOM_PERSONAS_FILE)) {
      customPersonas = JSON.parse(fs.readFileSync(CUSTOM_PERSONAS_FILE, 'utf8'))
    }

    // Base mock persona template based on v3.json structure
    const newPersona = {
      name: {
        lastupdated: "2020-09-10",
        source: "1",
        classification: "C",
        value: name || "Mock User"
      },
      nationality: {
        lastupdated: "2020-09-10",
        code: nationality || "SG",
        source: "1",
        classification: "C",
        desc: nationality === "SG" ? "SINGAPORE CITIZEN" : "FOREIGNER"
      },
      householdincome: {
        lastupdated: "2020-09-10",
        high: { value: incomeHigh !== undefined ? incomeHigh : 5000 },
        low: { value: incomeLow !== undefined ? incomeLow : 0 },
        source: "2",
        classification: "C"
      },
      sex: {
        lastupdated: "2020-09-10",
        code: "M",
        source: "1",
        classification: "C",
        desc: "Male"
      },
      schoolname: {
        lastupdated: "2020-09-10",
        source: "2",
        classification: "C",
        value: schoolName || ""
      },
      edulevel: {
        lastupdated: "2020-09-10",
        code: eduLevel || "",
        source: "2",
        classification: "C",
        desc: ""
      },
      marital: {
        lastupdated: "2020-09-10",
        code: maritalStatus || "1",
        source: "1",
        classification: "C",
        desc: ""
      },
      childrenbirthrecords: Array.from({length: noOfChildren || 0}).map((_, i) => ({
        birthcertno: { value: `T000000${i}Z` }
      })),
      regadd: {
        lastupdated: "2020-09-10",
        source: "1",
        classification: "C",
        type: "SG",
        line1: { value: regAdd || "" }
      },
      mobileno: {
        lastupdated: "2020-09-10",
        source: "2",
        classification: "C",
        areacode: { value: "65" },
        prefix: { value: "+" },
        nbr: { value: mobileNo || "" }
      },
      email: {
        lastupdated: "2020-09-10",
        source: "2",
        classification: "C",
        value: email || ""
      },
      password: {
        lastupdated: "2020-09-10",
        source: "1",
        classification: "C",
        value: password
      }
    }

    if (dynamic_age !== undefined && dynamic_age !== null) {
      newPersona.dynamic_age = dynamic_age
    } else if (dob) {
      newPersona.dob = {
        lastupdated: "2020-09-10",
        source: "1",
        classification: "C",
        value: dob
      }
    }

    customPersonas[nric] = newPersona
    fs.writeFileSync(CUSTOM_PERSONAS_FILE, JSON.stringify(customPersonas, null, 2))

    // Update assertions in memory
    assertions.myinfo.v3.personas[nric] = newPersona
    
    // Check if it exists in oidc.singPass, if so, update, else push
    const existingSp = assertions.oidc.singPass.find(p => p.nric === nric)
    if (existingSp) {
      existingSp.password = password
      existingSp.claims = newPersona
    } else {
      assertions.oidc.singPass.push({
        nric,
        password,
        claims: newPersona
      })
    }

    res.json({ success: true, message: 'Persona saved successfully' })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

module.exports = router
