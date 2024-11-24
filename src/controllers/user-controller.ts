import { Request, Response } from "express";
import UserService from "../services/user-service";

export default class UserController {
  constructor(private readonly userService: UserService) {}

  // Register a new user
  async register(req: Request, res: Response): Promise<Response> {
    const { email, password, fullName } = req.body;

    try {
      const user = await this.userService.register(email, password, fullName);
      return res
        .status(201)
        .json({ message: "User registered successfully", user });
    } catch (error: any) {
      return res.status(400).json({ message: error.message });
    }
  }

  // Authenticate a user
  async login(req: Request, res: Response): Promise<Response> {
    const { email, password } = req.body;

    try {
      const user = await this.userService.authenticate(email, password);
      return res.status(200).json({ message: "Login successful", user });
    } catch (error: any) {
      return res.status(401).json({ message: error.message });
    }
  }

  // Get user by ID
  async getUserById(req: Request, res: Response): Promise<Response> {
    const { id } = req.params;

    try {
      const user = await this.userService.getUserById(id);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      return res.status(200).json(user);
    } catch (error: any) {
      return res.status(500).json({ message: error.message });
    }
  }
}
