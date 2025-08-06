const User = require("../models/User.js");
const OTP = require("../models/OTP");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const otpGenerator = require("otp-generator");
require("dotenv").config();
const mailSender = require("../utils/mailSender");
const otpTemplate = require("../mail/templates/emailVerificationTemplate");
const Profile = require("../models/Profile");



exports.sendotp = async (req,res) => {
    try{
        const {email} = req.body
        
        const existingUser = await User.findOne({email});

        if(existingUser){
            return res.status(401).json({
                success:false,
                message:"User is already registered.",
            });
        }

        
        //Generate OTP until it is unique and doesn't exist in the DB
        var otp = otpGenerator.generate(6,{
            upperCaseAlphabets:false,
            lowerCaseAlphabets:false,
            specialChars:false,
        });

        console.log("OTP generated:",otp);

        let result = await OTP.findOne({otp:otp});

        while(result){
            var otp = otpGenerator.generate(6,{
                upperCaseAlphabets:false,
                lowerCaseAlphabets:false,
                specialChars:false,
            });

            result = await OTP.findOne({otp:otp});
        }

        const otpPayload = {email,otp}
        const otpBody = await OTP.create(otpPayload);
        console.log(otpPayload);

        res.status(200).json({
            success:true,
            message:"OTP sent successfully.",
            otp
        });

        // Send notification email
		try {
			const emailResponse = await mailSender(email, "Verification from Studynotion",otpTemplate(otp));
		} 
        
        catch (error) {
			// If there's an error sending the email, log the error and return a 500 (Internal Server Error) error
			console.error("Error occurred while sending email:", error);
			return res.status(500).json({
				success: false,
				message: "Error occurred while sending email",
				error: error.message,
			});

         }

    }

    catch(error){
        console.log(error);
        return res.status(500).json({
            success:false,
            message:"Error in OTP generation.",
        });
    }
}



exports.signup = async(req,res) => {
    try{
        const {
            firstName,
            lastName,
            email,
            password,
            confirmPassword,
            accountType,
            contactNumber,
            otp
        } = req.body

        if(!firstName || !lastName || !email || !password || !confirmPassword || !accountType || !contactNumber || !otp){
            return res.status(403).json({
                success:false,
                message:"Details missing.",
            });
        }

        if(password !== confirmPassword){
            return res.status(400).json({
                success:false,
                message:"Passwords do not match."
            });
        }

        if(await User.findOne({email})){
            return res.status(400).json({
                success:false,
                message:"User already is registered."
            });
        }


        //Check the most recently generated otp for the user
        const recentOtp = await OTP.findOne({email}).sort({createdAt:-1}).limit(1);
        console.log("Recent OTP:",recentOtp.otp);

        if(recentOtp.otp.length==0){
            return res.status(400).json({
                success:false,
                message:"OTP not found"
            });
        }

        else if(recentOtp.otp !== otp){
            return res.status(400).json({
                success:false,
                message:"Invalid OTP"
            });
        }

        const hashedpassword = await bcrypt.hash(password,10);

        const profileDetails = await Profile.create(
            {
                gender:null,
                dateOfBirth:null,
                about:null,
                contactNumber:null
            }
        );

        const user = await User.create({
            firstName,
            lastName,
            email,
            contactNumber,
            password:hashedpassword,
            accountType,
            additionalDetails:profileDetails._id,
            image:`https://api.dicebear.com/5.x/initials/svg?seed=${firstName} ${lastName}`,
        });

        return res.status(200).json({
            success:true,
            message:"Registeration successfull!"
        });

    }

    catch(error){
        console.log(error);
        return res.status(400).json({
            success:false,
            message:"Error in signing up.",
        });
    }
}


exports.login = async(req,res) => {
    try{
        const {email,password} = req.body;

        if(!email || !password){
            return res.status(403).json({
                success:false,
                message:"Email or password missing."
            });
        }

        
        const userExists = await User.findOne({email}).populate("additionalDetails");
       

        if(!userExists){
            return res.status(401).json({
                success:false,
                message:"User is not registered. Please sign up."
            });
        }


        if(await bcrypt.compare(password,userExists.password)){
            const payload = {
                email:userExists.email,
                id:userExists._id,
                acountType:userExists.accountType
            }

            const token = jwt.sign(payload,process.env.JWT_SECRET,{
                expiresIn:"2h"
            });

            userExists.token = token;
            userExists.password = undefined;

            const options = {
                expires:new Date(Date.now() + 3*24*60*1000),
                httpOnly:true,
            }

            res.cookie("token",token,options).status(200).json({
                success:true,
                userExists,
                token,
                message:"Logged in successfully!"
            }); 
        }

        else{
            return res.status(401).json({
                sucess:false,
                message:"Incorrect password."
            });
        }
    }

    catch(error){
        return res.status(400).json({
            success:false,
            message:"Failed to login."
        });
    }
}


exports.changePassword = async (req, res) => {
	try {
		// Get user data from req.user
		const userDetails = await User.findById(req.user.id);

		// Get old password, new password, and confirm new password from req.body
		const { oldPassword, newPassword, confirmNewPassword } = req.body;

		// Validate old password
		const isPasswordMatch = await bcrypt.compare(
			oldPassword,
			userDetails.password
		);
		if (!isPasswordMatch) {
			// If old password does not match, return a 401 (Unauthorized) error
			return res
				.status(401)
				.json({ success: false, message: "The password is incorrect" });
		}

		// Match new password and confirm new password
		if (newPassword !== confirmNewPassword) {
			// If new password and confirm new password do not match, return a 400 (Bad Request) error
			return res.status(400).json({
				success: false,
				message: "The password and confirm password does not match",
			});
		}

		// Update password
		const encryptedPassword = await bcrypt.hash(newPassword, 10);
		const updatedUserDetails = await User.findByIdAndUpdate(
			req.user.id,
			{ password: encryptedPassword },
			{ new: true }
		);

		// Send notification email
		try {
			const emailResponse = await mailSender(
				updatedUserDetails.email,
				passwordUpdated(
					updatedUserDetails.email,
					`Password updated successfully for ${updatedUserDetails.firstName} ${updatedUserDetails.lastName}`
				)
			);
			console.log("Email sent successfully:", emailResponse.response);
		} catch (error) {
			// If there's an error sending the email, log the error and return a 500 (Internal Server Error) error
			console.error("Error occurred while sending email:", error);
			return res.status(500).json({
				success: false,
				message: "Error occurred while sending email",
				error: error.message,
			});
		}

		// Return success response
		return res
			.status(200)
			.json({ success: true, message: "Password updated successfully" });
	} catch (error) {
		// If there's an error updating the password, log the error and return a 500 (Internal Server Error) error
		console.error("Error occurred while updating password:", error);
		return res.status(500).json({
			success: false,
			message: "Error occurred while updating password",
			error: error.message,
		});
	}
};