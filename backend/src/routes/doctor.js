const express = require("express");
const { Verify } = require("../middlewares/jwt");
const { requireDoctorCert } = require("../middlewares/doctorCert");

const router = express.Router();

router.get("/hello",Verify,requireDoctorCert,(req, res) => {
    
    if (req.user.role !== "doctor") {
      return res.status(403).json({ error: "doctor role required" });
    }
    if (req.user.username !== req.doctor.username) {
      return res.status(403).json({ error: "certificate/user mismatch" });
    }

    res.json({
      ok: true,
      message: `Hello Dr. ${req.doctor.username}!`,
      userFromSession: req.user,
      certSerial: req.doctor.serialNumber,
    });
  }
);

module.exports = router;
