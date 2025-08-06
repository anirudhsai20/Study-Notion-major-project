const User = require("../models/User");
const Course = require("../models/Course");
const mailsender = require("../utils/mailSender");
const {courseEnrollmentEmail} = require("../mail/templates/courseEnrollmentEmail");
const {default:mongoose} = require("mongoose");

exports.capturePayment = async(req,res) => {
    const userId = req.user.id;
    const {course_id} = req.body;

    if(!course_id){
        return res.status(400).json({
            success:false,
            message:"Please provide a valid course ID."
        });
    }

    let course;

    try{
        course = await Course.findById(course_id);
        if(!course){
            return res.status(400).json({
                success:false,
                message:"Course not found."
            });
        }

        const uid = new mongoose.Types.ObjectId(userId);
        if(course.studentsEnrolled.includes(uid)){
            return res.status(200).json({
                success:false,
                message:"Student is already enrolled."
            });
        }
    }

    catch(error){
        return res.status(500).json({
            success:false,
            message:error.message
        });
    }


    //create order
    const amount = course.price;
    const currency = "INR";

    const options = {
        amount:amount*100,
        currency,
        receipt: Math.random(Date.now()).toString(),
        notes:{
            courseId:course_id,
            userId
        }
    }

    //Initiate the payment using Razorpay
    try{
        const paymentResponse = await instance.orders.create(options);
        console.log(paymentResponse);

        return res.status(200).json({
            success:true,
            courseName:course.courseName,
            courseDescription:course.courseDescription,
            thumbnail: course.thumbnail,
            orderId: paymentResponse.id,
            currency:paymentResponse.currency,
            amount:paymentResponse.amount,
        });
        
    }

    catch(error){
        console.log(error);
        res.json({
            success:false,
            message:"Could not initiate order",
        });
    }
    
}


//Verify signature of Razorpay and Server

exports.verifySignature = async(req,res) => {
    const webhookSecret = "123123";
    const signature = req.headers["x-razorpay-signature"];
    
    const shasum = crypto.createHmac("sha256",webhookSecret);
    shasum.update(JSON.stringify(req.body));
    const digest = shasum.digest("hex");

    if(signature === digest) {
        console.log("Payment is Authorised");

        const {courseId, userId} = req.body.payload.payment.entity.notes;

        try{
                //fulfil the action

                //find the course and enroll the student in it
                const enrolledCourse = await Course.findOneAndUpdate(
                                                {_id: courseId},
                                                {$push:{studentsEnrolled: userId}},
                                                {new:true},
                );

                if(!enrolledCourse) {
                    return res.status(500).json({
                        success:false,
                        message:'Course not Found',
                    });
                }

                console.log(enrolledCourse);

                //find the student andadd the course to their list enrolled courses me 
                const enrolledStudent = await User.findOneAndUpdate(
                                                {_id:userId},
                                                {$push:{courses:courseId}},
                                                {new:true},
                );

                console.log(enrolledStudent);

                //mail send krdo confirmation wala 
                const emailResponse = await mailSender(
                                        enrolledStudent.email,
                                        "Congratulations from CodeHelp",
                                        "Congratulations, you are onboarded into new CodeHelp Course",
                );

                console.log(emailResponse);
                return res.status(200).json({
                    success:true,
                    message:"Signature Verified and COurse Added",
                });


        }       
        catch(error) {
            console.log(error);
            return res.status(500).json({
                success:false,
                message:error.message,
            });
        }
    }
    else {
        return res.status(400).json({
            success:false,
            message:'Invalid request',
        });
    }
}
