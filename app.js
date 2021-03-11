/**
 * ================== README ==================
 * This is a simple endpoint that takes in a userId token(jwt token) and 
 * a profileImage(base64 string), it will generate 2 smaller 
 * version of the original image and store them on Amazon S3(distributed blob store)
 * unnecessary code was removed to make it simple
 * 
 * This is just a demonstration of knowledge of the express framework
 * error exception handling is removed for better reading experience 
 * it is suboptimal for production use
 * 
 * A better way to implement such feature is :
 * when there's a upload to the profileImage bucket, 
 * it triggers an event, the event is waiting on a message queue
 * and ready to be consume a lambda, the lambda will that go and resize it asynchronously 
 * and write back to the S3, resizing is CPU, IO intensive, javascript is not the 
 * best pick
 */
const express = require('express');
const helmet = require('helmet');
const xss = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');
const compression = require('compression');
const cors = require('cors');
const passport = require('passport');
const { jwtStrategy } = require('./config/passport');
const { authLimiter } = require('./middlewares/rateLimiter');
const routes = require('./routes/v1');
const { errorConverter, errorHandler } = require('./middlewares/error');
const ApiError = require('./utils/ApiError');
const Joi = require('joi'); // middleware for input validation
const isBase64 = require('is-base64'); // check if given base 64 string is valid or not 
const jimp = require('jimp'); // jimp is a cross platform Image Manipulation library
const { S3Client, PutObjectCommand }= require("@aws-sdk/client-s3"); // s3 client to save the image

const app = express();
const client = new S3Client({ region: process.env.REGION });
const PORT = process.env.EXPRESS_PORT;
const db = require('./somedatabase'); // depends on the situation we can have a connection pool or just one instance here

// middleware 

// set security HTTP headers
app.use(helmet());
// parse json request body
app.use(express.json());
// parse urlencoded request body
app.use(express.urlencoded({ extended: true }));
// sanitize request data
app.use(xss());
app.use(mongoSanitize());
// gzip compression
app.use(compression());
// enable cors
app.use(cors());
app.options('*', cors());
// jwt authentication
app.use(passport.initialize());
passport.use('jwt', jwtStrategy);
// limit repeated failed requests to auth endpoints
if (process.env.NODE_ENV === 'production') {
  app.use('/v1/auth', authLimiter);
}
// v1 api routes
app.use('/v1', routes);
// send back a 404 error for any unknown api request
app.use((req, res, next) => {
  next(new ApiError(httpStatus.NOT_FOUND, 'Not found'));
});
// convert error to ApiError, if needed
app.use(errorConverter);
// handle error
app.use(errorHandler);

/**
 * image resizer, resize the image into 2 size:
 *      small: 50 * 50 
 *      medium: 200 * 200
 * @param {Buffer} data - buffer of the original image
 */
const resizer = async (data) => {
    return jimp.read(data).then(image => {
        const small = image.clone().resize(50, 50).quality(60);
        const medium = image.clone().resize(200, 200).quality(60);
        return [small, medium]
    });
}

/**
 * image resizer, resize the image into 2 size:
 *      small: 50 * 50 
 *      medium: 200 * 200
 */
const formatURL = (region, bucketName, key) => {
    return `https://s3-${region}.amazonaws.com/${bucketName}/${key}`
}

const handler = async (req, res) => {
    // middleware validates the idtoken and we make sure userId match with that
    let { userID, profileImage } = req.body; 

    // jimp doesnt like the header of base 64
    let largeBuffer = Buffer.from(profileImage.replace(/^data:image\/\w+;base64,/, ""), 'base64');

    // error should be handle properly here
    const resizerRes = await resizer(largeBuffer); 
    const getBufferPromise = resizerRes.map(p => p.getBufferAsync(jimp.AUTO));
    const [ smallBuffer, mediumBuffer ] = await Promise.all(getBufferPromise);
    
    const fileParms = [{
        "Body": smallBuffer,
        "Bucket": "com.nameofthebuket.something",
        "Key": `${id}/small.jpg` 
        }, 
        {
        "Body": mediumBuffer,
        "Bucket": "com.nameofthebuket.something",
        "Key": `${id}/medium.jpg` 
        },{
        "Body": largeBuffer,
        "Bucket": "com.nameofthebuket.something",
        "Key": `${id}/large.jpg` 
    }];

    const urls = []
    for (let params of fileParms) {
        const command = new PutObjectCommand(params);
        await client.send(command);
        urls.push(formatURL(process.env.REGION, params.Bucket, params.Key))
    }
    try {
        await db.collection("User").updateOne({
            _id: ObjectId(userID)
        },{
            $set:{
                profile:{
                    small: urls[0],
                    medium: urls[1], 
                    large: urls[2]
                }
            }
        },{
            upsert:true
        })
        res.json({
            status: "success",
            data: {
                small: urls[0], 
                medium: urls[1], 
                large: urls[2]
            }
        });
    } catch(err){
        res.json(WELL_FORMATTED_ERROR_RESPONSE); 
    }
}

const schema = Joi.object({
    userID: Joi.string().required(),
    profileImage: Joi.string().custom((value, helper) => {
        if (isBase64(value, { mimeRequired: true, allowEmpty: false }))
            return true;
        else {
            return helper.message("profile_img must be base64 mime string")
        }
    })
});

app.post('/profile', validate(schema), handler);
app.listen(PORT, () => console.log(`listening at http://localhost:${PORT}`));

