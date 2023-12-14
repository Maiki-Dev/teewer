import express from 'express';
import { updateUser, deleteUser, getUser, getUsers } from '../controllers/user.js';
import { verifyToken } from '../utils/verifyToken.js';

const router = express.Router()

router.get("/checkauthentication", verifyToken, (req,res,next)=>{
    res.send("hello user, LOGGING TEST")
})
//UPDATE
router.put("/:id", updateUser)
//DELETE
router.delete("/:id", deleteUser);
//GET
router.get("/:id", getUser);
//GET ALL
router.get("/", getUsers);

export default router;