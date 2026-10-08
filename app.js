import express from "express";
import authRouter from "./routes/auth.routes.js";

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get("/", (req, res) => {
	res.json({
		message: "Teaching App API is running"
	})
})

app.use("/auth", authRouter);

app.listen(PORT, () => {
	console.log(`Server is running on port ${PORT}`);
})