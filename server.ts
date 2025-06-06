import express, { Application } from "express";
import dotenv from "dotenv";
import connectDB from "./src/config/database-config";
import swaggerUi from "swagger-ui-express";
import swaggerJSDoc from "swagger-jsdoc";
import { notFound, errorHandler } from "./src/middlewares/error-middleware";
import UserRoutes from "./src/routes/user-route";
import ProfileRoutes from "./src/routes/profile-route";
import VehicleRoutes from "./src/routes/vehicle-route";
<<<<<<< HEAD
import cors from "cors";
import adminRoutes from './src/routes/admin-route';
import adminAuthRoutes from './src/routes/admin-auth-route';
=======
import StationRoutes from "./src/routes/station-route";
import cors from "cors";
>>>>>>> 2ef7dcf44cf11a3a99ca9907205f20bee56614bb

dotenv.config();

const app: Application = express();
const PORT = process.env.PORT || 8080;
const DOMAIN_URL = process.env.DOMAIN_URL || "http://localhost";

connectDB();

<<<<<<< HEAD
import Admin from './src/models/admin';

const createDefaultAdmin = async () => {
  const existingAdmin = await Admin.findOne({});
  if (!existingAdmin) {
    await Admin.create({ username: 'admin', password: 'admin' });
    console.log('✅ Default admin created');
  }
};

createDefaultAdmin();


=======
>>>>>>> 2ef7dcf44cf11a3a99ca9907205f20bee56614bb
app.use(cors());
app.use(express.json());

// Swagger definition
const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "EVAT API",
      version: "1.0.0",
      description: "API documentation for EVAT App",
    },
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
          in: "header",
        },
      },
    },
    security: [
      {
        bearerAuth: [],
      },
    ],
    servers: [{ url: `${DOMAIN_URL}:${PORT}` }],
  },
  apis: ["./src/routes/*.ts", "./src/routes/*.js"],
};

// Initialize swagger-jsdoc
const swaggerSpec = swaggerJSDoc(options);

// Serve Swagger UI
app.use(
  "/api/docs",
  swaggerUi.serve,
  swaggerUi.setup(swaggerSpec, { explorer: true })
);

<<<<<<< HEAD
=======
app.get("/api-docs/json", (req, res) => {
  res.json(swaggerSpec);
});

>>>>>>> 2ef7dcf44cf11a3a99ca9907205f20bee56614bb
// User Route
app.use("/api/auth", UserRoutes);
app.use("/api/profile", ProfileRoutes);
app.use("/api/vehicle", VehicleRoutes);
<<<<<<< HEAD
app.use('/api/admin', adminRoutes);
app.use('/api/admin-auth', adminAuthRoutes);
=======
app.use("/api/chargers", StationRoutes); // As laid out in teams https://teams.microsoft.com/l/message/19:7206bda1ca594fa2a18709af5d9fb718@thread.v2/1743116771178?context=%7B%22contextType%22%3A%22chat%22%7D
>>>>>>> 2ef7dcf44cf11a3a99ca9907205f20bee56614bb

// Middleware
app.use(notFound);
app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`Server is running on ${DOMAIN_URL}:${PORT}`);
  console.log(`Swagger UI is available on ${DOMAIN_URL}:${PORT}/api/docs`);
});
