/**
 * Global JS variables related to Login Tab
 */
var qrCodeTab = "#qrcodeloginli";
var loginTab = "#loginli";

/**
 * Global JS variables related to password login
 */
var singPassID = "#loginID";
var password= "#password";
var captca = "#jCaptcha";
var captcaImg = "#logincap";

var loginBlock = "#LoginForm"; 
var logincaptchaBlock = "#loginc";
var loginerrorMessageBlock= "#errorMessage";
var captchaErrorMsgBlock= "#captchaErrMsg";

/**
 * Global JS variables related to QR Code
 */
var hasScanned = "has-scanned";
var isExpired = "is-expired";
var cantGen = "cant-gen";
var isUnavailable = "is-unavailable";
var isSuspended = "is-suspended";
var isLocked = "is-locked";

var isQrCodeGenerated = false;
var qrCodeInitStartTime = 0;

/*******************************************************************************
 *SOFT TOKEN RELATED METHODS START
 ******************************************************************************/

//this javascript method is used for app link for web kit singpass in esevice login
function initAppLauncher(spmurl) {
    NativeAppLauncher.init({
            appLauncherElId: 'qrcodelink', // Element Id of App Launcher button. 
            notSupportedMessage: 'Sorry, QR Login is not compatible with this browser. Please try another.', // Defaults to 'Not Supported!'
            universalLinkUrl: spmurl,
            appUri: 'https',
            appDeepUri: 'spm',
            androidAppId: 'sg.ndi.sp',
            iOsAppStore: 'https://itunes.apple.com/app/singpass-mobile/id1340660807?ls=1&mt=8',
            debug: false // Optional
    });
}
/**
 * This method will start the listener for 2 minutes.After 2 minutes.The
 * listener expires.
 * 
 * @param succesUrl
 * @param logoutUrl
 * @returns
 */
function startTwofaPushNotifResponseListener(succesUrl) {

    $.ajax({
        url : "/spauth/tfa/userpnreslistener",
        type : "GET",
        cache: false,
        complete : function(response) {
            var responseObj = response.responseJSON;
            if (responseObj.threadCounter < 2){
                startTwofaPushNotifResponseListener(succesUrl);
            } else if (responseObj.listenerStatus === "SUCCESS") {
                window.location.href = succesUrl;
            }
        },
        error : function(xhr, status, error) {
            startTwofaPushNotifResponseListener(succesUrl);
        }
    })
};

/**
 * This method is execute the scanned listener via ajax call.
 * 
 * 
 * @returns 
 */
function startQRCodeScannedResponseListener() {

    $.ajax({
        url : spauthContextPath + "/login/qrscannedlistener",
        type : "GET",
        cache: false,
        global: false,
        complete : function(response) {
            var responseObj = response.responseJSON;
            // check if the request is timeout and validate the no of times the thread has been called for same transaction id
            if (responseObj.listenerStatus === "SUCCESS" && responseObj.userStatus == null) {
                if (browserLogin !== 'DESKTOP') {
                    if (document.visibilityState === 'visible') {
                         startQRCodeAcknowledgedResponseListener();
                         $('.qr__wrapper').addClass(hasScanned);
                    } else {
                        document.addEventListener("visibilitychange", function() {
                             if (document.visibilityState === 'visible') {
                                 startQRCodeAcknowledgedResponseListener();
                                 $('.qr__wrapper').addClass(hasScanned);
                             }
                        });
                    }
                } else {
                    startQRCodeAcknowledgedResponseListener();
                    $('.qr__wrapper').addClass(hasScanned);
                }
            } else if (responseObj.listenerStatus === 'RETRY') {
                if (browserLogin !== 'DESKTOP')  {
                    if (document.visibilityState === 'visible') {
                        startQRCodeScannedResponseListener();
                    } else {
                        document.addEventListener("visibilitychange", function() {
                            if (document.visibilityState === 'visible') {
                                startQRCodeScannedResponseListener();
                            }
                        });
                    }
                } else {
                     startQRCodeScannedResponseListener();
                }
            } else if (responseObj.listenerStatus === "ERROR") {
                $('.qr__wrapper').addClass(cantGen);
            } else if (responseObj.listenerStatus === "EXPIRED") {
                $('.qr__wrapper').addClass(isExpired);
            } else if (responseObj.userStatus === "SPCP004D" || responseObj.userStatus === "SPCP004E") {
                $('.qr__wrapper').addClass(isLocked);
            } else if (responseObj.userStatus === "SPCP003" || responseObj.userStatus === "SPCP004A" || responseObj.userStatus === "SPCP004B" || responseObj.userStatus === "SPCP004C" || responseObj.userStatus === "SPCP005" || responseObj.userStatus === "SPCP006") {
                $('.qr__wrapper').addClass(isSuspended);
            }
        },
        error : function(xhr, status, error) {
            startQRCodeScannedResponseListener();
        }
    });
}

/**
 * This method is execute the acknowledged listener via ajax call clean the previous
 * active the scanned and acknowledged listener is session storage
 * 
 * @returns 
 */
function startQRCodeAcknowledgedResponseListener() {
    var form = $("#qrcodelogin");

    $.ajax({
        url : spauthContextPath + "/login/qracknowledgedlistener",
        type : "POST",
        cache: false,
        global: false,
        data: $(form).serialize() + "&wogaaid=" + initialiseWogaaId(),
        complete : function(response) {
            var responseObj = response.responseJSON;
            if (responseObj.listenerStatus === "SUCCESS") {
               setCookie("tabId","qrcodetab");

               // to send wogaa request
               if (!isSingpassHome) {
                   sendWogaaRequest(responseObj.wogaaUrl, responseObj.wogaaMessage);
               }

               // to redirect to given page
               doPostRequest("verifyqrcodeauth");
            } else if (responseObj.listenerStatus === 'RETRY') {
                if (browserLogin !== 'DESKTOP') {
                    if (document.visibilityState === 'visible') {
                        startQRCodeAcknowledgedResponseListener();
                    } else {
                        document.addEventListener("visibilitychange", function() {
                            if (document.visibilityState === 'visible') {
                                startQRCodeAcknowledgedResponseListener();
                            }
                        });
                    }
                } else {
                    startQRCodeAcknowledgedResponseListener();
                }
            } else if (responseObj.listenerStatus === "ERROR") {
               $('.qr__wrapper').addClass(cantGen);
            } else  if (responseObj.listenerStatus === "EXPIRED") {
               $('.qr__wrapper').addClass(isExpired);
            }
        },
        error : function(xhr, status, error) {
            startQRCodeAcknowledgedResponseListener();
        }
    });
}

function refreshQRCode() {
     isQrCodeGenerated = false;
     generateQRCode();
}

 /**
  * This method generate the QR code. 
  * Page will reload when the session has time out.
  * 
  * @returns 
  */
function generateQRCode() {

   if (isQrCodeGenerated) {
        return; 
   } else {
          $('.qr__wrapper').removeClass(cantGen);
          $('.qr__wrapper').removeClass(isExpired);
          $('.qr__wrapper').removeClass(isLocked);
          $('.qr__wrapper').removeClass(isSuspended);
          $('.qr__wrapper').removeClass(hasScanned);

          $.ajax({
              url : spauthContextPath + "/login/generateqrcode",
              type : "POST",
              cache: false,
              success : function(response) {
                  var responseObj = response;

                  if (responseObj.error === 136) {
                      if (isSingpassHome === true) {
                          doPostRequest("/spauth/login/logout");
                          // To refresh the page so that user can successfully login
                          window.location.reload();
                      } else {
                          window.location.replace("/spauth/login/eservicelogout");
                      }
                  } else if (responseObj.qrcode_byte != null) {
                       $('#qrcodelink').addClass('flip').delay(500).queue(function(){
                           initAppLauncher(responseObj.spm_url);
                           $('#qrImage').attr("src", "data:image/png;base64," + responseObj.qrcode_byte);
                           $('#qrcodelink').removeClass('flip').dequeue();
                       });

                       isQrCodeGenerated = true;
                       startQRCodeScannedResponseListener();
                       qrCodeInitStartTime = Date.now();
                  } else if (responseObj.qrcode_is_unavailable) {
                      $('.qr__wrapper').addClass(isUnavailable);
                  } else {
                      $('.qr__wrapper').addClass(cantGen);
                  }
              },
              error: function(XMLHttpRequest, textStatus, errorThrown) { 
                  $('.qr__wrapper').addClass(cantGen);
              }
          });
    }
}

/**
 *  Helper method to open new tab upon clicking on qr code
 *  Close the window after one second ( for user login experience )
 * @param url 
 * @returns
 */
function redirectToSingPassMobile(url) {
    var spmwindow = window.open(url, "_blank");
}

/**
 * This method will get the QR Validity Time (value for loading screen timeout)
 * 
 * @return time in milliseconds that will be used for setting the timeoutQRLoadingScreen global variable.
 * Note that negative values will skip loading screen.
 */
function getQRValidityTime() {
    var timeoutQRLoadingScreen = 120000 - (Date.now() - qrCodeInitStartTime);
    if (timeoutQRLoadingScreen == 0) {
        timeoutQRLoadingScreen = -1;
    }
    return timeoutQRLoadingScreen;
}

/*******************************************************************************
 *SOFT TOKEN RELATED METHODS ENDS
 ******************************************************************************/

/*******************************************************************************
 *CAPTCHA RELATED METHODS STARTS
 ******************************************************************************/

/**
 * This method is called when user clicked cancel button in captcha page
 * 
 * @param divIdToHide
 * @param divIdToDisplay
 */
function doCancelCaptcha(divToHide, divToDisplay) {
    $(divToHide).hide();
    $(divToDisplay).show();
    $("#jCaptcha").val("");
}

/**
 * This method is called when user Singpass ID / Password retries is more than 3
 * times.
 * 
 * @param flow
 * @param captchId
 * @param hideList
 * @param showList
 * @param captchUrl
 * @returns
 */
function isUserRetriesReachedMax(captchId, hideList, showList, captchUrl) {
    showElements(showList);
    hideElements(hideList);
    $(captchId).attr("src", captchUrl);
}

/**
 * This method is called when user entered invalid captcha
 * @param flow
 * @param captchId
 * @param errorMessageId
 * @param clearList
 * @param hideList
 * @param showList
 * @param captchUrl
 * @returns
 */
function invalCap(captchId, errorMessageId, clearList, hideList, showList, captchUrl){
    clear(clearList);
    showElements(showList);
    $(captchId).attr("src", captchUrl);
    $(errorMessageId).text("Incorrect code. Please try again.");
}

/*******************************************************************************
 *CAPTCHA RELATED METHODS ENDS
 ******************************************************************************/

/*******************************************************************************
 * COMMON LOGIN RELATED METHODS STARTS
 ******************************************************************************/

/**
 * This is common method to show the elements based on the idlist given as
 * parameter
 * 
 * @param {List}
 *            IdList
 * @returns
 */
function showElements(IdList) {
    var len = IdList.length;
    for (i = 0; i < len; i++) {
        $(IdList[i]).show();
    }
}

/**
 * This is common method to hide the elements based on the idlist given as
 * parameter
 * 
 * @param IdList
 * @returns
 */
function hideElements(IdList) {
    var len = IdList.length;
    for (i = 0; i < len; i++) {
        $(IdList[i]).hide();
    }
}

/**
 * This is common method to clear the values based on idlist given as the
 * parameter
 * 
 * @param IdList
 * @returns
 */
function clear(IdList) {
    var len = IdList.length;
    for (i = 0; i < len; i++) {
        $(IdList[i]).val("");
    }
}

/**
 * This is method that trim the value with value given in the parameter
 * @param x
 * @returns x after trim.
 */
function myTrim(x) {
    return x.replace(/(^[ \t]*\n)/gm, "");
}

/**
 * This method listens to changes in userID entry to redirect user when id is clicked
 */
function redirectID() {
    const idInput = document.getElementById("id-input");
    const optionsList = document.getElementById("id-datalist");
    let optionsMap = new Map();
    for (let i=0; i<optionsList.options.length; i++) {
        optionsMap.set(optionsList.options[i].value, optionsList.options[i].dataset.asserturl);
    }
    if (optionsMap.has(idInput.value)) {
        const assertURL = optionsMap.get(idInput.value);
        window.location.href = assertURL;
    }
}

/**
 * This is generic method called for onkeypress action.
 * 
 * @param e
 * @param action
 * @param lflow
 * @returns
 */
function doKeyPress(e, action) {

    var keynum;
    if (window.event) { // IE
        keynum = e.keyCode;
    } else if (e.which) { // Netscape/Firefox/Opera
        keynum = e.which;
    }
    if (keynum == 13) {
        if (action == 'LOGIN' || action == 'captcha') {
            doSubmit(action);
        }
    }
    return;
}

function getCookie(key) {
    var keyValue = document.cookie.match('(^|;) ?' + key + '=([^;]*)(;|$)');
    return keyValue ? keyValue[2] : null;
}

function setRememberTab(){
    var tabId = getCookie("tabId");
    return tabId;
}

function setCookie(key, value) {
    var expires = new Date();
    expires.setTime(expires.getTime() + (1 * 24 * 60 * 60 * 1000));
    document.cookie = key + '=' + value + ';expires=' + expires.toUTCString();
}

/**
 * This is generic method to show qr code tab.
 */
function showQRCodeTab() {
    $(qrCodeTab).addClass('active');
    $('#sectionB').addClass('active');
    $(loginTab).removeClass('active');
    $('#sectionA').removeClass('active');
    generateQRCode();
}

/**
 * This is generic method to show login tab.
 */
function showLoginTab() {    
    $(qrCodeTab).removeClass('active');
    $('#sectionB').removeClass('active');
    $(loginTab).addClass('active');
    $('#sectionA').addClass('active in');
}

function showLoadTab(){
    var tabId = setRememberTab();
    if (tabId == 'qrcodetab'){
        showQRCodeTab();
    } else {
        showLoginTab();
    }

    toggleQRTooltip();
}

/**
 * Shows QR Tooltip if login tab is active
 */
function toggleQRTooltip() {
    if(!$(qrCodeTab).hasClass('active')) {
        $('#sp-mobile-tooltip').show();
    } else {
        $('#sp-mobile-tooltip').hide();
    }
}

/* 
 * Sets the modal top position to be placed just below the mobile-header
 */
function setModalTopPos() {
    var modalTopPos = $('#mobile-header').position().top + $('#mobile-header').outerHeight();
    modalTopPos > 0 ? $('#myModalHorizontal').find('.homepageLogin.modal-dialog').css('top', modalTopPos+'px') : $('#myModalHorizontal').find('.homepageLogin.modal-dialog').attr('style', ''); 
}

/**
 * This method is to check if the user password is eight character.
 * @param password
 * @returns
 */
function isEightChar(password) {
    if (password.length == 8) {
        return true;
    }
} 

/**
 * This method is called when user clicked cancel button.
 * 
 * @param URL
 * @returns
 */
function doCancel(URL) {
    window.location = URL;
}

/**
 * This method is to validate singPassID and Password  entered is empty
 * @param userId
 * @param password
 * @param errorDivId
 * @returns false if values is is empty
 */
function validateUserIdPassword(userId, password, errorDivId){
       if (userId.length == 0 && password.length == 0) {
             $(errorDivId).css("display", "block");
             $(errorDivId).text("Please enter your SingPass ID and Password");
             return false;
       }
       return true;
  }

/**
 * Method to validate the mandatory fields
 */
function validateMandatoryFields(actionType) {
    var userId = $("#loginID").val();
    var password = $("#password").val();
    var captchaVal = $("#jCaptcha").val();
    if (actionType === 'LOGIN' && userId.length == 0 && password.length == 0) {
        document.getElementById('errorMessage').style.display = "block";
        document.getElementById('errorMessage').innerHTML = "Please enter your SingPass ID and Password";
        return false;
    } else if (actionType === 'LOGIN' && userId.length == 0) {
        $('#password').val("");
        document.getElementById('errorMessage').style.display = "block";
        document.getElementById('errorMessage').innerHTML = "Please enter your SingPass ID.";
        return false;
    } else if (actionType === 'LOGIN' && password.length == 0) {
        document.getElementById('errorMessage').style.display = "block";
        document.getElementById('errorMessage').innerHTML = "Please enter your SingPass password.";
        return false;
    } else if (actionType === 'captcha' && captchaVal.length == 0) {
        $('#captchaErrMsg').show();
        $('#captchaErrMsg').text("Enter the code shown above.");
        return false;
    }
    return true;
}

/**
 * This method is to validate singPassID is empty or not
 * 
 * @param userId
 * @param errorDivId
 * @param errorMessage
 * @returns false if values is is empty
 */
function validateUserId(userId, errorDivId, errorMessage,hideErrorDiv) {
    if (userId.length == 0) {
        $(errorDivId).css("display", "block");
        $(errorDivId).text(errorMessage);
        $("#plLockedErrorMessage").hide();
        return false;
    }
    return true;
}

/**
 * This method is validate password is empty or not
 * 
 * @param password
 * @param errorDivId
 * @param errorMessage
 * @returns if values is is empty
 */
function validatePassword(password, errorDivId, errorMessage) {
    if (password.length == 0) {
        $(errorDivId).css("display", "block");
        $(errorDivId).text(errorMessage);
        $("#plpLockedErrorMessage").hide();
        return false;
    }
    return true;
}

/**
 *  This method to check the mandatory validation 
 * @param userId
 * @param password
 * @param errorDivId
 * @param errorMessage
 * @param pErrorMessage
 * @returns
 */
function mandatoryValidation(userId, password, errorDivId, errorMessage, pErrorMessage){
      var validation = validateUserIdPassword(userId, password, errorDivId);
      if(validation){
          validation = validateUserId(userId, errorDivId, errorMessage);
          if(validation){
              validation = validatePassword(password, errorDivId, pErrorMessage);
          }
      }
      return validation;
}

/**
 * This is a common methods used to set all the rba related details
 * 
 * @param flow
 * @param obj
 * @param data
 * @param modulussec
 * @param deviceDetId
 * @param encryptedRbaDeviceId
 * @param rbaDeviceParamId
 * @returns
 */
function setRBAData(obj, data, modulussec, deviceDetId, encryptedRbaDeviceId, rbaDeviceParamId) {
    var jsonString;
    var encryptedRbaDevice;
    var rbaDeviceParam2;
    try {
        var Exponent = obj.EXPONENT;
        var Modulus = obj.RSA_PUBLIC_KEY;
        var randomString16 = obj.RANDOM_STRING_16;
        var rsaBlock = encryptVerifyNoUserRSABlock256(Exponent, Modulus, data,randomString16);
        jsonString = JSON.stringify(jsonObj);
    } catch (e) {
       //doNothing
    }
    $(deviceDetId).val(jsonString);
}

/**
 * This is a common method used to set all the randoms details for password encyrpt.
 * @param obj
 * @param password
 * @param randomString16Id
 * @param randomString32Id
 * @param randomString64Id
 * @param rsaBlockId
 * @param rsaBlock1Id
 * @param rsaBlock2Id
 * @returns
 */
function setRamdoms(obj, password, randomString16Id, randomString32Id, randomString64Id, rsaBlockId, rsaBlock1Id, rsaBlock2Id) {
    var Exponent = obj.EXPONENT;
    var Modulus = obj.RSA_PUBLIC_KEY;
    var randomString16 = obj.RANDOM_STRING_16;
    var randomString32 = obj.RANDOM_STRING_32;
    var randomString64 = obj.RANDOM_STRING_64;

    var rsaBlock = encryptVerifyNoUserRSABlock256(Exponent, Modulus, password,randomString16);
    var rsaBlock1 = encryptMigratePwdNoVerifyNoUser256RSABlock512(Exponent,Modulus, password, randomString32, randomString64);
    var rsaBlock2 = encryptVerifyStaticNoUserRSABlock512(Exponent, Modulus,password, randomString64);

    $(randomString16Id).val(randomString16);
    $(randomString32Id).val(randomString32);
    $(randomString64Id).val(randomString64);
    $(rsaBlockId).val(rsaBlock);
    $(rsaBlock1Id).val(rsaBlock1);
    $(rsaBlock2Id).val(rsaBlock2);
}


/**
 * This method is to hide and show list when user is invalid user
 * 
 * @param flow
 * @param errorMessageId
 * @param clearList
 * @param hideList
 * @param showList
 * @param message
 * @returns
 */
function invalUsr(flow, errorMessageId, clearList, hideList, showList, message) {
    clear(clearList);
    hideElements(hideList);
    showElements(showList);
    $(errorMessageId).text(message);
}

/**
 * This method is to hide and show list when user is locked/suspend/terminated user
 * @param flow
 * @param errorMessageId
 * @param clearList
 * @param hideList
 * @param showList
 * @param message
 * @returns
 */
function commErr(flow, errorMessageId, clearList, hideList, showList, message) {
    clear(clearList);
    hideElements(hideList);
    showElements(showList);
    $(errorMessageId).text(message);
}

/**
 * This method hide and show login and captcha form elements based on the error message return.
 * @param errorMessage
 * @returns
 */
function invalidLoginAction(errorMessage, captchaVal) {

    if (errorMessage == 'invalUsr') {
        // Login Form
        $("#LoginForm").show();
        $('#loginID').val("");
        $('#password').val("");
        $('#errorMessage').show();
        $('#errorMessage').text("You have entered an invalid SingPass ID or Password.");
        // Captcha Form
        $("#loginc").hide();
        $("#jCaptcha").val("");
        $('#captchaErrMsg').hide();
    } else if (errorMessage == 'commErr') {
        // Login Form
        $("#LoginForm").show();
        $('#loginID').val("");
        $('#password').val("");
        $('#errorMessage').show();
        $('#errorMessage').text("We are unable to verify your account. Please reset your password. Alternatively, you can contact the SingPass helpdesk for more information.");
        // Captcha Form
        $("#loginc").hide();
        $("#jCaptcha").val("");
        $('#captchaErrMsg').hide();
    } else if (errorMessage == 'isUserRetriesReachedMax') {
        // Login Form
        $("#LoginForm").hide();
        $('#errorMessage').hide();
        // Captcha Form
        $("#loginc").show();
        $("#jCaptcha").val("");
        $('#captchaErrMsg').hide();
        $('#logincap').attr('src', captchaVal);
    } else if (errorMessage == 'invalCap') {
        // Login Form
        $("#LoginForm").hide();
        $('#errorMessage').hide();
        // Captcha Form
        $("#loginc").show();
        $("#jCaptcha").val("");
        $('#captchaErrMsg').show();
        $('#captchaErrMsg').text("Incorrect code. Please try again.");
        $('#logincap').attr('src', captchaVal);
    } else if (errorMessage == 'notActiveIrasUsr') {
        $("#LoginForm").show();
        $('#loginID').val("");
        $('#password').val("");
        $('#errorMessage').show();
        $('#errorMessage').html("Please set up the <a href='https://singpassmobile.sg/' target='_blank'>SingPass Mobile app</a> on your mobile device to access SingPass or IRAS Digital Services");
        // Captcha Form
        $("#loginc").hide();
        $("#jCaptcha").val("");
        $('#captchaErrMsg').hide();
    } else {
        $("#LoginForm").show();
        $('#loginID').val("");
        $('#password').val("");
        $('#errorMessage').show();
        $('#errorMessage').html(errorMessage);
        // Captcha Form
        $("#loginc").hide();
        $("#jCaptcha").val("");
        $('#captchaErrMsg').hide();
    }
}

/*******************************************************************************
 * WOGAA RELATED METHODS STARTS
 ******************************************************************************/

/**
 * This method will initialise WOGAA ID.
 * 
 * @return wogaaId - WOGAA ID.
 */
function initialiseWogaaId() {
    var wogaaId = "";
    try {
        wogaaId = _satellite.getVisitorId().getMarketingCloudVisitorID();
        if (wogaaId == null || wogaaId == undefined) {
            wogaaId = "";
        }
    } catch (error) {
        wogaaId = error.message;
    }
    return wogaaId;
}

/**
 * This method will send a POST request to WOGAA.
 * 
 * @param wogaaUrl
 *            contains WOGAA API URL.
 * @param wogaaMessage
 *            contains a string to be sent to WOGAA.
 */
function sendWogaaRequest(wogaaUrl, wogaaMessage) {

    try {
        if (wogaaUrl !== null && wogaaUrl !== undefined) {
            var wogaaRequest = new XMLHttpRequest();
            wogaaRequest.open("POST", wogaaUrl, true);
            wogaaRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            wogaaRequest.onerror = function(error) {
                // do nothing
            }
            wogaaRequest.send(wogaaMessage);
        }
    } catch (error) {
        // do nothing
    }
}

/*******************************************************************************
 * WOGAA RELATED METHODS ENDS
 ******************************************************************************/

/*******************************************************************************
 * COMMON LOGIN RELATED METHODS ENDS
 ******************************************************************************/
