const {
  verifyToken,
  verifyTokenAndAuthorization,
  verifyTokenAndAdmin,
} = require("./verifyToken");
const User = require("../models/User");
const bcrypt = require('bcryptjs'); // For password hashing

const router = require("express").Router();
//CREATE
router.post("/", verifyTokenAndAdmin, async (req, res) => {
  const newUser = new User(req.body);
  try {
    const savedUser = await newUser.save();
    res.status(200).json(savedUser);
  } catch (error) {
    res.status(500).json(error);
  }
});
// UPDATE
router.put("/:id", verifyToken, async (req, res) => {
  try {
    // If password is provided, hash it
    if (req.body.password) {
      const salt = await bcrypt.genSalt(10);
      req.body.password = await bcrypt.hash(req.body.password, salt);
    }

    // Find and update the user
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      {
        $set: req.body,
      },
      { new: true }
    );

    // Handle case where user is not found
    if (!updatedUser) {
      return res.status(404).json("User not found.");
    }

    // Exclude the password field from the response
    const { password, ...others } = updatedUser._doc;
    res.status(200).json(others);
  } catch (error) {
    console.error("Error updating user:", error); // Log detailed error
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message }); // Include error message in response
  }
});

// DELETE
router.delete("/:id", verifyTokenAndAuthorization, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.status(200).json("User has been deleted!");
  } catch (error) {
    res.status(500).json(error);
  }
});
// GET USER
router.get("/find/:id", verifyTokenAndAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    const { password, ...others } = user._doc; //user._doc
    res.status(200).json({ ...others });
  } catch (error) {
    res.status(500).json(error);
  }
});
// GET ALL USERS
router.get("/", verifyTokenAndAdmin, async (req, res) => {
  const query = req.query.new;
  try {
    const users = query
      ? await User.find().sort({ _id: -1 }).limit(5)
      : await User.find();
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json(error);
  }
});
// GET USER STATS
router.get("/stats", verifyTokenAndAdmin, async (req, res) => {
  const date = new Date();
  const lastYear = new Date(date.setFullYear(date.getFullYear() - 1));
  try {
    const data = await User.aggregate([
      { $match: { createdAt: { $gte: lastYear } } },
      {
        $project: {
          month: { $month: "$createdAt" },
        },

      },
      {
        $group: {
          _id: "$month",
          total :{$sum : 1} // every registered user
        }
      }
    ]);
    res.status(200).json(data);
  } catch (error) {
    res.status(500).json(error);
  }
});
module.exports = router;
