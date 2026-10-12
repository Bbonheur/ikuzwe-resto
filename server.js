require("dotenv").config();

const express = require("express");

const cors = require("cors");

const mongoose = require("mongoose");

const http = require("http");

const crypto = require("crypto");

const bcrypt = require("bcryptjs");

const jwt = require("jsonwebtoken");

const { Server } = require("socket.io");

const Order = require("./models/order");

const Admin = require("./models/Admin");

const sendVerificationEmail = require("./utils/sendVerificationEmail");

const app = express();

const server = http.createServer(app);

const PORT = process.env.PORT || 5000;

const allowedOrigins = [

  "http://localhost:5173",

  "http://localhost:5174",

  ...(process.env.FRONTEND_URL

    ? [process.env.FRONTEND_URL]

    : []),

];

const io = new Server(server, {

  cors: {

    origin: allowedOrigins,

    methods: ["GET", "POST", "PATCH"],

  },

});

app.use(cors({ origin: allowedOrigins }));

app.use(express.json({ limit: "100kb" }));

const ALLOWED_STATUSES = [

  "Pending",

  "Preparing",

  "Ready",

  "Delivered",

  "Cancelled",

];

const PAYMENT_METHODS = [

  "Cash",

  "Mobile Money",

  "Card",

];

function getOrderRoom(orderNumber) {

  return `order:${String(orderNumber).trim()}`;

}

function hashCode(code) {

  return crypto

    .createHash("sha256")

    .update(String(code))

    .digest("hex");

}

function publicAdmin(admin) {

  return {

    id: admin._id,

    name: admin.name,

    username: admin.username,

    email: admin.email,

  };

}

// --------------------------------------------------

// AUTHENTICATION MIDDLEWARE

// --------------------------------------------------

async function requireAdmin(req, res, next) {

  try {

    const authorization = req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {

      return res.status(401).json({

        message: "Authentication required. Please log in.",

      });

    }

    const token = authorization.slice(7).trim();

    if (!token) {

      return res.status(401).json({

        message: "Authentication token is missing.",

      });

    }

    const payload = jwt.verify(token, process.env.JWT_SECRET);

    if (typeof payload.sub !== "string") {

      return res.status(401).json({

        message: "Invalid authentication token.",

      });

    }

    const admin = await Admin.findById(payload.sub);

    if (!admin || !admin.isActive || !admin.isEmailVerified) {

      return res.status(401).json({

        message: "Admin account is unavailable.",

      });

    }

    req.admin = admin;

    next();

  } catch (error) {

    if (

      error.name === "JsonWebTokenError" ||

      error.name === "TokenExpiredError"

    ) {

      return res.status(401).json({

        message: "Your session is invalid or expired. Please log in again.",

      });

    }

    console.error("Admin authentication failed:", error.message);

    return res.status(500).json({

      message: "Authentication could not be completed.",

    });

  }

}

// --------------------------------------------------

// SOCKET.IO

// --------------------------------------------------

io.on("connection", (socket) => {

  console.log("Socket connected:", socket.id);

  socket.on("joinOrderRoom", async (orderNumber) => {

    try {

      if (

        typeof orderNumber !== "string" ||

        !orderNumber.trim()

      ) {

        return;

      }

      const normalizedOrderNumber = orderNumber.trim();

      const orderExists = await Order.exists({

        orderNumber: normalizedOrderNumber,

      });

      if (!orderExists) {

        socket.emit("orderRoomError", {

          message: "Order not found.",

        });

        return;

      }

      socket.join(getOrderRoom(normalizedOrderNumber));

    } catch (error) {

      console.error("Failed to join order room:", error.message);

    }

  });

  socket.on("disconnect", () => {

    console.log("Socket disconnected:", socket.id);

  });

});

// --------------------------------------------------

// HEALTH CHECK

// --------------------------------------------------

app.get("/", (req, res) => {

  res.json({

    message: "Ikuzwe Restaurant API is running!",

    database:

      mongoose.connection.readyState === 1

        ? "Connected"

        : "Not connected",

    realtime: "Socket.IO enabled",

    adminAuthentication: "Enabled",

  });

});

// --------------------------------------------------

// ADMIN: REGISTER THE FIRST ACCOUNT

// POST /api/admin/register

// --------------------------------------------------

app.post("/api/admin/register", async (req, res) => {

  let registrationLockAcquired = false;

  try {

    const { name, username, email, password } = req.body;

    if (

      typeof name !== "string" ||

      !name.trim() ||

      name.trim().length > 100 ||

      typeof username !== "string" ||

      !/^[a-zA-Z0-9_.-]{3,50}$/.test(username.trim()) ||

      typeof email !== "string" ||

      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) ||

      email.trim().length > 254 ||

      typeof password !== "string" ||

      password.length < 10 ||

      password.length > 128

    ) {

      return res.status(400).json({

        message:

          "Provide a valid name, username, email, and password of 10–128 characters.",

      });

    }

    // Acquire an atomic MongoDB lock so simultaneous registration

    // requests cannot create multiple initial admin accounts.

    const locks = mongoose.connection.collection(

      "admin_registration_locks"

    );

    try {

      await locks.insertOne({

        _id: "initial-admin",

        createdAt: new Date(),

      });

      registrationLockAcquired = true;

    } catch (error) {

      if (error.code === 11000) {

        return res.status(403).json({

          message:

            "Admin registration is closed. Please use the login page.",

        });

      }

      throw error;

    }

    // The lock stays in place once registration begins.

    // Check the database as an additional safeguard.

    const existingAdmin = await Admin.exists({});

    if (existingAdmin) {

      return res.status(403).json({

        message:

          "An admin account already exists. Please log in.",

      });

    }

    const normalizedUsername = username.trim().toLowerCase();

    const normalizedEmail = email.trim().toLowerCase();

    const duplicate = await Admin.findOne({

      $or: [

        { username: normalizedUsername },

        { email: normalizedEmail },

      ],

    });

    if (duplicate) {

      return res.status(409).json({

        message: "Username or email is already registered.",

      });

    }

    const verificationCode = crypto

      .randomInt(0, 1000000)

      .toString()

      .padStart(6, "0");

    const admin = await Admin.create({

      name: name.trim(),

      username: normalizedUsername,

      email: normalizedEmail,

      passwordHash: await bcrypt.hash(password, 12),

      isEmailVerified: false,

      isActive: true,

      verificationCodeHash: hashCode(verificationCode),

      verificationCodeExpiresAt: new Date(

        Date.now() + 10 * 60 * 1000

      ),

      verificationAttempts: 0,

    });

    try {

      await sendVerificationEmail(

        normalizedEmail,

        verificationCode,

        admin.name

      );

    } catch (emailError) {

      // Do not leave a partially registered account if delivery fails.

      await Admin.deleteOne({ _id: admin._id });

      // Allow another attempt only if no admin has been created.

      await locks.deleteOne({ _id: "initial-admin" });

      registrationLockAcquired = false;

      console.error(

        "Verification email failed:",

        emailError.message

      );

      return res.status(503).json({

        message:

          "Could not send the verification email. Check Gmail settings and try again.",

      });

    }

    return res.status(201).json({

      message:

        "Registration started. Check your email for the verification code.",

      email: normalizedEmail,

      expiresInSeconds: 600,

    });

  } catch (error) {

    console.error("Admin registration failed:", error.message);

    if (error.code === 11000) {

      return res.status(409).json({

        message: "Username or email is already registered.",

      });

    }

    return res.status(500).json({

      message: "Admin registration failed.",

    });

  }

});

// --------------------------------------------------

// ADMIN: VERIFY EMAIL

// POST /api/admin/verify-email

// --------------------------------------------------
// --------------------------------------------------
// ADMIN: RESEND EMAIL VERIFICATION CODE
// POST /api/admin/resend-verification
// --------------------------------------------------

app.post("/api/admin/resend-verification", async (req, res) => {
  try {
    const { email } = req.body;

    if (typeof email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      return res.status(400).json({
        message: "Enter a valid email address.",
      });
    }

    const admin = await Admin.findOne({
      email: email.trim().toLowerCase(),
    }).select(
      "+verificationCodeHash +verificationCodeExpiresAt +verificationAttempts"
    );

    // Use a generic response to avoid revealing account status.
    if (!admin || admin.isEmailVerified || !admin.isActive) {
      return res.status(200).json({
        message: "If the account needs verification, a new code will be sent.",
      });
    }

    const verificationCode = crypto
      .randomInt(0, 1000000)
      .toString()
      .padStart(6, "0");

    admin.verificationCodeHash = hashCode(verificationCode);
    admin.verificationCodeExpiresAt = new Date(
      Date.now() + 10 * 60 * 1000
    );
    admin.verificationAttempts = 0;

    await admin.save();

    try {
      await sendVerificationEmail(
        admin.email,
        verificationCode,
        admin.name
      );
    } catch (emailError) {
      console.error("Resending verification email failed:", emailError.message);

      return res.status(503).json({
        message: "Could not send the verification email. Please try again later.",
      });
    }

    return res.status(200).json({
      message: "A new verification code has been sent to your email.",
    });
  } catch (error) {
    console.error("Resend verification failed:", error.message);

    return res.status(500).json({
      message: "Could not resend the verification code.",
    });
  }
});

app.post("/api/admin/verify-email", async (req, res) => {

  try {

    const { email, code } = req.body;

    if (

      typeof email !== "string" ||

      typeof code !== "string" ||

      !/^\d{6}$/.test(code)

    ) {

      return res.status(400).json({

        message: "Enter your email and the six-digit verification code.",

      });

    }

    const admin = await Admin.findOne({

      email: email.trim().toLowerCase(),

    }).select(

      "+verificationCodeHash +verificationCodeExpiresAt +verificationAttempts"

    );

    if (!admin) {

      return res.status(400).json({

        message: "Invalid email or verification code.",

      });

    }

    if (admin.isEmailVerified) {

      return res.status(200).json({

        message: "Email is already verified. Please log in.",

      });

    }

    if (

      !admin.verificationCodeHash ||

      !admin.verificationCodeExpiresAt ||

      admin.verificationCodeExpiresAt.getTime() < Date.now()

    ) {

      return res.status(400).json({

        message: "Verification code expired. Contact support.",

      });

    }

    if (admin.verificationAttempts >= 5) {

      return res.status(429).json({

        message:

          "Too many verification attempts. Contact support.",

      });

    }

    admin.verificationAttempts += 1;

    if (

      hashCode(code) !== admin.verificationCodeHash

    ) {

      await admin.save();

      return res.status(400).json({

        message: "Invalid email or verification code.",

      });

    }

    admin.isEmailVerified = true;

    admin.verificationCodeHash = undefined;

    admin.verificationCodeExpiresAt = undefined;

    admin.verificationAttempts = 0;

    await admin.save();

    return res.status(200).json({

      message: "Email verified successfully. You can now log in.",

    });

  } catch (error) {

    console.error("Email verification failed:", error.message);

    return res.status(500).json({

      message: "Could not verify your email.",

    });

  }

});

// --------------------------------------------------

// ADMIN: LOGIN

// POST /api/admin/login

// --------------------------------------------------

app.post("/api/admin/login", async (req, res) => {

  try {

    const { identifier, password } = req.body;

    if (

      typeof identifier !== "string" ||

      !identifier.trim() ||

      typeof password !== "string" ||

      !password

    ) {

      return res.status(400).json({

        message: "Enter your username/email and password.",

      });

    }

    const normalizedIdentifier = identifier.trim().toLowerCase();

    const admin = await Admin.findOne({

      $or: [

        { username: normalizedIdentifier },

        { email: normalizedIdentifier },

      ],

    }).select("+passwordHash");

    if (

      !admin ||

      !(await bcrypt.compare(password, admin.passwordHash))

    ) {

      return res.status(401).json({

        message: "Invalid username/email or password.",

      });

    }

    if (!admin.isEmailVerified) {

      return res.status(403).json({

        message: "Please verify your email before logging in.",

      });

    }

    if (!admin.isActive) {

      return res.status(403).json({

        message: "This admin account is disabled.",

      });

    }

    if (!process.env.JWT_SECRET) {

      throw new Error("JWT_SECRET is missing.");

    }

    const token = jwt.sign(

      {

        sub: admin._id.toString(),

        type: "admin",

      },

      process.env.JWT_SECRET,

      {

        expiresIn: "8h",

        issuer: "ikuzwe-restaurant",

        audience: "ikuzwe-admin",

      }

    );

    return res.status(200).json({

      message: "Login successful.",

      token,

      expiresIn: 28800,

      admin: publicAdmin(admin),

    });

  } catch (error) {

    console.error("Admin login failed:", error.message);

    return res.status(500).json({

      message: "Login could not be completed.",

    });

  }

});

// --------------------------------------------------

// ADMIN: CHECK CURRENT SESSION

// GET /api/admin/me

// --------------------------------------------------

app.get("/api/admin/me", requireAdmin, (req, res) => {

  res.json({

    admin: publicAdmin(req.admin),

  });

});

// --------------------------------------------------

// CUSTOMER: CREATE AN ORDER

// POST /api/orders

// --------------------------------------------------

app.post("/api/orders", async (req, res) => {

  try {

    const {

      orderNumber,

      customerName,

      phone,

      customerPhone,

      numberOfClients,

      tableNumber,

      items,

      totalAmount,

      paymentMethod,

      status,

    } = req.body;

    if (

      typeof orderNumber !== "string" ||

      !orderNumber.trim() ||

      typeof customerName !== "string" ||

      !customerName.trim() ||

      typeof (phone || customerPhone) !== "string" ||

      !(phone || customerPhone).trim() ||

      !Number.isInteger(Number(numberOfClients)) ||

      Number(numberOfClients) < 1 ||

      !tableNumber ||

      !Array.isArray(items) ||

      items.length === 0 ||

      !Number.isFinite(Number(totalAmount)) ||

      Number(totalAmount) < 0

    ) {

      return res.status(400).json({

        message: "Please provide all required order information.",

      });

    }

    const validItems = items.every(

      (item) =>

        item &&

        typeof item.name === "string" &&

        item.name.trim() &&

        Number.isInteger(Number(item.quantity)) &&

        Number(item.quantity) > 0 &&

        Number.isFinite(Number(item.price)) &&

        Number(item.price) >= 0

    );

    if (!validItems) {

      return res.status(400).json({

        message: "One or more order items are invalid.",

      });

    }

    if (

      paymentMethod &&

      !PAYMENT_METHODS.includes(paymentMethod)

    ) {

      return res.status(400).json({

        message: "Invalid payment method.",

      });

    }

    if (status && status !== "Pending") {

      return res.status(400).json({

        message: "New orders must start with Pending status.",

      });

    }

    const normalizedOrderNumber = orderNumber.trim();

    const newOrder = await Order.create({

      orderNumber: normalizedOrderNumber,

      customerName: customerName.trim(),

      customerPhone: (phone || customerPhone).trim(),

      numberOfClients: Number(numberOfClients),

      tableNumber: String(tableNumber).trim(),

      items: items.map((item) => ({

        name: item.name.trim(),

        quantity: Number(item.quantity),

        price: Number(item.price),

      })),

      totalAmount: Number(totalAmount),

      paymentMethod: paymentMethod || "Cash",

      status: "Pending",

    });

    io.emit("order:new", newOrder);

    return res.status(201).json({

      message: "Order saved successfully!",

      order: newOrder,

    });

  } catch (error) {

    console.error("Failed to save order:", error.message);

    if (error.code === 11000) {

      return res.status(409).json({

        message: "This order number already exists. Please try again.",

      });

    }

    if (error.name === "ValidationError") {

      return res.status(400).json({

        message: "Order validation failed.",

        error: error.message,

      });

    }

    return res.status(500).json({

      message: "Failed to save order.",

    });

  }

});

// --------------------------------------------------

// ADMIN ONLY: GET ALL ORDERS

// GET /api/orders

// --------------------------------------------------

app.get("/api/orders", requireAdmin, async (req, res) => {

  try {

    const orders = await Order.find().sort({ createdAt: -1 });

    return res.json({

      count: orders.length,

      orders,

    });

  } catch (error) {

    console.error("Failed to retrieve orders:", error.message);

    return res.status(500).json({

      message: "Failed to retrieve orders.",

    });

  }

});

// --------------------------------------------------

// ADMIN ONLY: UPDATE ORDER STATUS

// PATCH /api/orders/:orderNumber/status

// --------------------------------------------------

app.patch(

  "/api/orders/:orderNumber/status",

  requireAdmin,

  async (req, res) => {

    try {

      const { status } = req.body;

      if (!ALLOWED_STATUSES.includes(status)) {

        return res.status(400).json({

          message: "Invalid order status.",

          allowedStatuses: ALLOWED_STATUSES,

        });

      }

      const order = await Order.findOneAndUpdate(

        {

          orderNumber: req.params.orderNumber.trim(),

        },

        { $set: { status } },

        { new: true, runValidators: true }

      );

      if (!order) {

        return res.status(404).json({

          message: "Order not found.",

        });

      }

      io.to(getOrderRoom(order.orderNumber)).emit(

        "orderStatusUpdated",

        order

      );

      io.to(getOrderRoom(order.orderNumber)).emit(

        "orderUpdated",

        order

      );

      io.emit("order:updated", order);

      return res.json({

        message: "Order status updated successfully!",

        order,

      });

    } catch (error) {

      console.error("Failed to update order:", error.message);

      return res.status(500).json({

        message: "Failed to update order status.",

      });

    }

  }

);

// --------------------------------------------------

// CUSTOMER: TRACK ONE ORDER

// GET /api/orders/:orderNumber

// --------------------------------------------------

app.get("/api/orders/:orderNumber", async (req, res) => {

  try {

    const order = await Order.findOne({

      orderNumber: req.params.orderNumber,

    });

    if (!order) {

      return res.status(404).json({

        message: "Order not found.",

      });

    }

    return res.json({ order });

  } catch (error) {

    console.error("Failed to retrieve order:", error.message);

    return res.status(500).json({

      message: "Failed to retrieve order.",

    });

  }

});

// --------------------------------------------------

// START SERVER

// --------------------------------------------------

async function startServer() {

  try {

    if (!process.env.MONGODB_URI) {

      throw new Error("MONGODB_URI is missing from .env.");

    }

    if (!process.env.JWT_SECRET ||

        process.env.JWT_SECRET.length < 32) {

      throw new Error(

        "JWT_SECRET must be set to a random secret of at least 32 characters."

      );

    }

    await mongoose.connect(process.env.MONGODB_URI);

    console.log("MongoDB connected successfully!");

    server.listen(PORT, () => {

      console.log(`Server running at http://localhost:${PORT}`);

      console.log("Socket.IO real-time updates are enabled.");

      console.log("Admin authentication routes are enabled.");

    });

  } catch (error) {

    console.error("Server startup failed:", error.message);

    process.exit(1);

  }

}

startServer();
