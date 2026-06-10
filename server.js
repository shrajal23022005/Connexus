const express = require("express");
const mysql2 = require("mysql2");
const fileUpload = require("express-fileupload");
const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");
const path = require("path");
const fs = require("fs");
require("dotenv").config();
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const app = express();


app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],

                scriptSrc: [
                    "'self'",
                    "'unsafe-inline'",
                    "https://code.jquery.com",
                    "https://cdn.jsdelivr.net",
                    "https://cdnjs.cloudflare.com"
                ],

                scriptSrcAttr: [
                    "'unsafe-inline'"
                ],

                styleSrc: [
                    "'self'",
                    "'unsafe-inline'",
                    "https://cdn.jsdelivr.net",
                    "https://cdnjs.cloudflare.com",
                    "https://fonts.googleapis.com"
                ],

                fontSrc: [
                    "'self'",
                    "https://fonts.gstatic.com",
                    "https://cdnjs.cloudflare.com"
                ],

                imgSrc: [
                    "'self'",
                    "data:",
                    "blob:"
                ],

                connectSrc: [
                    "'self'",
                    "https://cdn.jsdelivr.net",
                    "https://cdnjs.cloudflare.com"
                ]
            }
        }
    })
);

app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Too many requests. Try again later."
}));

// ======================
// MIDDLEWARE
// ======================

app.use(express.static("public"));

app.use(express.urlencoded({
    extended: true
}));

app.use(express.json());

app.use(
    fileUpload({
        createParentPath: true,
        limits: {
            fileSize: 2 * 1024 * 1024
        },
        abortOnLimit: true
    })
);

// ======================
// SERVER
// ======================

const PORT = process.env.DB_PORT || 1500;

app.listen(PORT, function () {
    console.log(`✅ Server Started on Port ${PORT}`);
});

// ======================
// DATABASE
// ======================
const dbConfig = {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    dateStrings: true,

    ssl: {
        rejectUnauthorized: true
    }
};

const mysql = mysql2.createConnection(dbConfig);

mysql.connect(function (err) {

    if (err == null) {
        console.log("✅ Connected to Database Successfully");
    }
    else {
        console.log("❌ DB Error:", err.message);
    }
});
// ======================
// AUTH MIDDLEWARE
// ======================

function verifyToken(req, resp, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return resp.status(401).send("Access Denied");
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return resp.status(401).send("Invalid or Expired Token");
    }
}

function isValidImage(file) {
    const allowedMimeTypes = ["image/jpeg", "image/png", "image/webp"];
    const allowedExtensions = [".jpg", ".jpeg", ".png", ".webp"];

    const ext = path.extname(file.name).toLowerCase();

    return (
        allowedMimeTypes.includes(file.mimetype) &&
        allowedExtensions.includes(ext)
    );
}

function verifyAdmin(req, resp, next) {
    verifyToken(req, resp, function () {
        if (req.user.utype !== "admin") {
            return resp.status(403).send("Admin Access Required");
        }

        next();
    });
}


// ======================
// NODEMAILER
// ======================

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS,
    },
});

// ======================
// ROUTES
// ======================

app.get("/", function (req, resp) {

    resp.sendFile(
        path.join(__dirname, "public/index.html")
    );
});

// ======================
// USER SIGNUP
// ======================

app.post("/user-signup", async function (req, resp) {

    try {

        let {
            txtsemail,
            txtspwd,
            typesselect
        } = req.body;

        if (
            !txtsemail ||
            !txtspwd ||
            !typesselect
        ) {
            return resp
                .status(400)
                .send("Please fill all fields");
        }

        mysql.query(
            "SELECT email FROM users WHERE email=?",
            [txtsemail],
            async function (err, result) {

                if (err) {
                    console.log(err);
                    return resp
                        .status(500)
                        .send("Database Error");
                }

                if (result.length > 0) {
                    return resp
                        .status(409)
                        .send("Email already exists");
                }

                try {

                    const hashedPassword =
                        await bcrypt.hash(txtspwd, 10);

                    mysql.query(
                        "INSERT INTO users(email,pwd,utype,status) VALUES(?,?,?,1)",
                        [
                            txtsemail,
                            hashedPassword,
                            typesselect
                        ],
                        function (err) {

                            if (err) {

                                console.log(err);

                                return resp
                                    .status(500)
                                    .send("Signup Failed");
                            }

                            resp.send("Signup Successful");
                        }
                    );

                } catch (e) {

                    console.log(e);

                    resp.status(500)
                        .send("Password Hash Error");
                }
            }
        );

    } catch (err) {

        console.log(err);

        resp.status(500).send("Server Error");
    }
});

// ======================
// USER LOGIN
// ======================

app.post("/user-login", function (req, resp) {

    let {
        txtlemail,
        txtlpwd
    } = req.body;

    if (!txtlemail || !txtlpwd) {
        return resp
            .status(400)
            .send("Missing Credentials");
    }

    mysql.query(
        "SELECT * FROM users WHERE email=?",
        [txtlemail],
        async function (err, result) {

            if (err) {

                console.log(err);

                return resp
                    .status(500)
                    .send("Database Error");
            }

            if (result.length == 0) {

                return resp
                    .status(401)
                    .send("Invalid Email");
            }

            let user = result[0];

            if (user.status == 0) {

                return resp
                    .status(403)
                    .send("User Blocked");
            }

            try {

                let match =
                    await bcrypt.compare(
                        txtlpwd,
                        user.pwd
                    );

                if (match) {

                    const token = jwt.sign(
                    {
                        email: user.email,
                        utype: user.utype
                    },
                    process.env.JWT_SECRET,
                    {
                        expiresIn: "1d"
                    }
                );

                resp.send({
                    status: true,
                    token,
                    email: user.email,
                    utype: user.utype
                });

                } else {

                    resp.status(401)
                        .send("Invalid Password");
                }

            } catch (e) {

                console.log(e);

                resp.status(500)
                    .send("Password Compare Error");
            }
        }
    );
});

// ======================
// FORGOT PASSWORD
// ======================

app.post("/forgot-pwd", async function (req, resp) {

    try {

        let email = req.body.txtemail;

        if (!email) {

            return resp
                .status(400)
                .send("Email Required");
        }

        mysql.query(
            "SELECT * FROM users WHERE email=?",
            [email],
            async function (err, result) {

                if (err) {

                    console.log(err);

                    return resp
                        .status(500)
                        .send("Database Error");
                }

                if (result.length == 0) {

                    return resp.send("If this email exists, password reset instructions will be sent");
                }

                let tempPassword =
                    Math.random()
                        .toString(36)
                        .slice(-8);

                let hashedPassword =
                    await bcrypt.hash(tempPassword, 10);

                mysql.query(
                    "UPDATE users SET pwd=? WHERE email=?",
                    [hashedPassword, email],
                    function (err) {

                        if (err) {

                            console.log(err);

                            return resp
                                .status(500)
                                .send("Update Failed");
                        }

                        let mailOptions = {

                            from:
                                process.env.MAIL_USER,

                            to: email,

                            subject: "Password Reset",

                            text:
                                "Your temporary password is: "
                                + tempPassword +
                                "\n\nPlease login and change your password immediately from settings."
                        };

                        transporter.sendMail(
                            mailOptions,
                            function (error) {

                                if (error) {

                                    console.log(error);

                                    return resp
                                        .status(500)
                                        .send("Mail Failed");
                                }

                                resp.send("If this email exists, password reset instructions will be sent");
                            }
                        );
                    }
                );
            }
        );

    } catch (err) {

        console.log(err);

        resp.status(500).send("Server Error");
    }
});

// ======================
// ADMIN USERS PAGE
// ======================

app.get("/adminusers", function (req, resp) {

    resp.sendFile(
        path.join(
            __dirname,
            "public/admin-users.html"
        )
    );
});

// ======================
// FETCH ALL USERS
// ======================

app.get("/fetch-all-users", verifyAdmin, function (req, resp) {

    mysql.query(
        "SELECT email,utype,status FROM users WHERE utype != ?",
        ["admin"],
        function (err, result) {

            if (err) {
                console.log(err);

                return resp
                    .status(500)
                    .send("Server Error");
            }

            resp.send(result);
        }
    );
});

// ======================
// DELETE USER
// ======================

app.post("/del-one", function (req, resp) {

    const email = req.body.email;

    if (!email) {
        return resp.status(400).send("Email missing");
    }

    mysql.query(
        "DELETE FROM users WHERE email=?",
        [email],
        function (err, result) {

            if (err) {
                console.log(err);
                return resp.status(500).send("Server Error");
            }

            if (result.affectedRows === 0) {
                return resp.status(404).send("User not found");
            }

            resp.send("Deleted Successfully");
        }
    );
});

// ======================
// BLOCK USER
// ======================

app.post("/block-one", verifyAdmin, function (req, resp) {

    mysql.query(
        "UPDATE users SET status=0 WHERE email=?",
        [req.body.email],
        function (err) {

            if (err) {

                console.log(err);

                return resp
                    .status(500)
                    .send("Server Error");
            }

            resp.send("User Blocked");
        }
    );
});

// ======================
// RESUME USER
// ======================

app.post("/resume-one", verifyAdmin, function (req, resp) {

    mysql.query(
        "UPDATE users SET status=1 WHERE email=?",
        [req.body.email],
        function (err) {

            if (err) {

                console.log(err);

                return resp
                    .status(500)
                    .send("Server Error");
            }

            resp.send("User Resumed");
        }
    );
});

// ======================
// FETCH ALL INFLUENCERS
// ======================

app.get("/fetch-all-infl", verifyAdmin, function (req, resp) {

    mysql.query(
        "SELECT * FROM iprofile",
        function (err, result) {

            if (err) {

                console.log(err);

                return resp
                    .status(500)
                    .send("Server Error");
            }

            resp.send(result);
        }
    );
});

// ======================
// ADMIN INFLUENCER PAGE
// ======================

app.get("/adminallinf", function (req, resp) {

    resp.sendFile(
        path.join(
            __dirname,
            "public/admin-all-infl.html"
        )
    );
});

// ======================
// FIND INFLUENCERS
// ======================

app.get("/do-find", function (req, resp) {

    const {
        fields,
        city,
        gender
    } = req.query;

    let query =
        "SELECT * FROM iprofile WHERE 1=1";

    let params = [];

    if (fields && fields.trim()) {

        query += " AND fields LIKE ?";

        params.push(`%${fields}%`);
    }

    if (city && city.trim()) {

        query += " AND city LIKE ?";

        params.push(`%${city}%`);
    }

    if (gender && gender.trim()) {

        query += " AND gender=?";

        params.push(gender);
    }

    mysql.query(
        query,
        params,
        function (err, result) {

            if (err) {

                console.log(err);

                return resp
                    .status(500)
                    .send("Server Error");
            }

            resp.send(result);
        }
    );
});

// ======================
// SEARCH CLIENT DETAILS
// ======================

app.get("/searchclient-details", verifyToken, function (req, resp) {

    mysql.query(
        "SELECT * FROM cprofile WHERE email=?",
        [req.query.CPemailinf],
        function (err, result) {

            if (err) {

                console.log(err);

                return resp
                    .status(500)
                    .send("Server Error");
            }

            resp.send(result);
        }
    );
});

// ======================
// CLIENT SAVE
// ======================

app.post("/client-save", function (req, resp) {

    const {
        CPemailinf,
        CPnameinf,
        CPcityinf,
        CPstateinf,
        CPorginf,
        CPmobinf,
    } = req.body;

    mysql.query(
        "INSERT INTO cprofile VALUES(?,?,?,?,?,?)",
        [
            CPemailinf,
            CPnameinf,
            CPcityinf,
            CPstateinf,
            CPorginf,
            CPmobinf,
        ],
        function (err) {

            if (err) {
                console.log("Client Save Error:", err);

                if (err.code === "ER_DUP_ENTRY") {
                    return resp.status(409).send("Client profile already exists. Use Update.");
                }

                return resp.status(500).send("Client Profile Save Failed");
            }

            resp.send("Client Profile Saved");
        }
    );
});

// ======================
// CLIENT UPDATE
// ======================

app.post("/client-update", function (req, resp) {

    const {
        CPemailinf,
        CPnameinf,
        CPcityinf,
        CPstateinf,
        CPorginf,
        CPmobinf,
    } = req.body;

    mysql.query(
        "UPDATE cprofile SET name=?,city=?,state=?,org=?,mobile=? WHERE email=?",
        [
            CPnameinf,
            CPcityinf,
            CPstateinf,
            CPorginf,
            CPmobinf,
            CPemailinf,
        ],
        function (err) {

            if (err) {

                console.log(err);

                return resp
                    .status(500)
                    .send("Server Error");
            }

            resp.send("Client Profile Updated");
        }
    );
});

// ======================
// BOOKINGS
// ======================

app.post("/infl-bookings", verifyToken, function (req, resp) {

    const {
        txtpbemail,
        txtpbevent,
        txtpbdate,
        txtpbtime,
        txtpbcity,
        txtpbvenue,
    } = req.body;

    mysql.query(
        "INSERT INTO events(emailid,events,doe,tos,city,venue) VALUES(?,?,?,?,?,?)",
        [
            txtpbemail,
            txtpbevent,
            txtpbdate,
            txtpbtime,
            txtpbcity,
            txtpbvenue,
        ],
        function (err) {

            if (err) {

                console.log(err);

                return resp
                    .status(500)
                    .send("Server Error");
            }

            resp.send("Event Booked Successfully");
        }
    );
});

// ======================
// FETCH EVENTS
// ======================

app.get("/fetch-all-events", verifyToken, function (req, resp) {
    mysql.query(
        "SELECT * FROM events WHERE emailid=?",
        [req.query.email],
        function (err, result) {

            if (err) {

                console.log(err);

                return resp
                    .status(500)
                    .send("Server Error");
            }

            resp.send(result);
        }
    );
});

// ======================
// DELETE EVENT
// ======================

app.delete("/del-one-events", verifyToken, function (req, resp) {

    mysql.query(
        "DELETE FROM events WHERE rid=?",
        [req.body.rid],
        function (err) {

            if (err) {

                console.log(err);

                return resp
                    .status(500)
                    .send("Server Error");
            }

            resp.send("Event Deleted");
        }
    );
});

// ======================
// SETTINGS
// ======================

app.post("/infl-settings", verifyToken, function (req, resp) {

    try {

        const {
            txtsettingsemail,
            txtoldpwd,
            txtnewpwd,
            txtconfirmpwd
        } = req.body;

        // 1. Validation
        if (!txtsettingsemail || !txtoldpwd || !txtnewpwd || !txtconfirmpwd) {
            return resp.status(400).send("All fields are required");
        }

        // 2. Password match check
        if (txtnewpwd !== txtconfirmpwd) {
            return resp.status(400).send("New passwords do not match");
        }

        // 3. Find user
        mysql.query(
            "SELECT * FROM users WHERE email=?",
            [txtsettingsemail],
            async function (err, result) {

                if (err) {
                    console.log(err);
                    return resp.status(500).send("Database Error");
                }

                if (result.length === 0) {
                    return resp.status(404).send("User Not Found");
                }

                let user = result[0];

                try {

                    // 4. Compare OLD password
                    const isMatch = await bcrypt.compare(txtoldpwd, user.pwd);

                    if (!isMatch) {
                        return resp.status(401).send("Old Password Incorrect");
                    }

                    // 5. Hash new password
                    const hashedPassword = await bcrypt.hash(txtnewpwd, 10);

                    // 6. Update DB
                    mysql.query(
                        "UPDATE users SET pwd=? WHERE email=?",
                        [hashedPassword, txtsettingsemail],
                        function (err) {

                            if (err) {
                                return resp.status(500).send("Update Failed");
                            }

                            return resp.send("Password Updated Successfully");
                        }
                    );

                } catch (e) {
                    console.log(e);
                    return resp.status(500).send("Password Processing Error");
                }

            }
        );

    } catch (err) {
        console.log(err);
        return resp.status(500).send("Server Error");
    }
});

// ======================
// SEARCH INFLUENCER DETAILS
// ======================

app.get("/search-details", verifyToken, function (req, resp) {

    mysql.query(
        "SELECT * FROM iprofile WHERE email=?",
        [req.query.txtemailinf],
        function (err, result) {

            if (err) {

                console.log(err);

                return resp
                    .status(500)
                    .send("Server Error");
            }

            resp.send(result);
        }
    );
});

// ======================
// SAVE INFLUENCER PROFILE
// ======================

app.post("/influencer-save", verifyToken, function (req, resp) {

    let fileName = "nopic.jpg";

    if (req.files && req.files.photo) {

        const file = req.files.photo;
        if (!isValidImage(file)) {
            return resp.status(400).send("Only JPG, PNG, or WEBP images are allowed");
        }
        fileName =
            Date.now() +
            path.extname(file.name);

        const uploadPath = path.join(
            __dirname,
            "public/uploads",
            fileName
        );

        file.mv(uploadPath, function (err) {

            if (err) {

                return resp
                    .status(500)
                    .send("File Upload Failed");
            }

            saveProfile();
        });

    } else {

        saveProfile();
    }

    function saveProfile() {

        let categories = "";

        if (
            Array.isArray(
                req.body.listcategoryi
            )
        ) {

            categories =
                req.body.listcategoryi.join(",");

        } else {

            categories =
                req.body.listcategoryi || "";
        }

        mysql.query(
            "INSERT INTO iprofile VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                req.body.txtemailinf,
                req.body.txtnameinf,
                req.body.txtgenderinf,
                req.body.dobinf,
                req.body.txtaddinf,
                req.body.txtcityinf,
                req.body.txtphninf,
                categories,
                req.body.txtinstainf,
                req.body.txtlinkedinf,
                req.body.txtyoutubeinf,
                req.body.txtotherinfoi,
                fileName,
            ],
            function (err) {

                if (err) {

                    console.log(err);

                    return resp
                        .status(500)
                        .send("Server Error");
                }

                resp.send(
                    "Profile Saved Successfully"
                );
            }
        );
    }
});

// ======================
// UPDATE INFLUENCER PROFILE
// ======================

app.post("/influencer-update", verifyToken, function (req, resp) {

    let fileName =
        req.body.hdn || "nopic.jpg";

    function updateProfile() {

        let categories = "";

        if (
            Array.isArray(
                req.body.listcategoryi
            )
        ) {

            categories =
                req.body.listcategoryi.join(",");

        } else {

            categories =
                req.body.listcategoryi || "";
        }

        mysql.query(
            `UPDATE iprofile 
            SET 
            iname=?,
            gender=?,
            dob=?,
            address=?,
            city=?,
            contact=?,
            fields=?,
            insta=?,
            fb=?,
            youtube=?,
            otheri=?,
            picpath=?
            WHERE email=?`,
            [
                req.body.txtnameinf,
                req.body.txtgenderinf,
                req.body.dobinf,
                req.body.txtaddinf,
                req.body.txtcityinf,
                req.body.txtphninf,
                categories,
                req.body.txtinstainf,
                req.body.txtlinkedinf,
                req.body.txtyoutubeinf,
                req.body.txtotherinfoi,
                fileName,
                req.body.txtemailinf,
            ],
            function (err) {

                if (err) {

                    console.log(err);

                    return resp
                        .status(500)
                        .send("Server Error");
                }

                resp.send(
                    "Profile Updated Successfully"
                );
            }
        );
    }

    if (req.files && req.files.photo) {

        const file = req.files.photo;
        if (!isValidImage(file)) {
            return resp.status(400).send("Only JPG, PNG, or WEBP images are allowed");
        }
        fileName =
            Date.now() +
            path.extname(file.name);

        const uploadPath = path.join(
            __dirname,
            "public/uploads",
            fileName
        );

        file.mv(uploadPath, function (err) {

            if (err) {

                return resp
                    .status(500)
                    .send("File Upload Failed");
            }

            updateProfile();
        });

    } else {

        updateProfile();
    }
});

// ======================
// PAGES
// ======================

app.get("/influencer-profile", function (req, resp) {

    resp.sendFile(
        path.join(
            __dirname,
            "public/inf-profile.html"
        )
    );
});

app.get("/events-manager", function (req, resp) {

    resp.sendFile(
        path.join(
            __dirname,
            "public/events-manager.html"
        )
    );
});