import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';

class SchemeWebauthn extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      module: props.module,
      name: props.name,
      profile: props.profile,
      registered: false,
      registration: false,
      idList: [],
      status: ""
    };
    
    this.getRegister = this.getRegister.bind(this);
    this.register = this.register.bind(this);
    this.testRegistration = this.testRegistration.bind(this);
    
    this.getRegister();
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      module: nextProps.module,
      name: nextProps.name,
      profile: nextProps.profile,
      registered: false,
      registration: false
    }, () => {
      this.getRegister();
    });
  }
  
  strToBin(str) {
    return Uint8Array.from(atob(str), c => c.charCodeAt(0));
  }

  binToStr(bin) {
    return btoa(new Uint8Array(bin).reduce(
      (s, byte) => s + String.fromCharCode(byte), ''
    ));
  }
  getRegister() {
    if (this.state.profile) {
      apiManager.glewlwydRequest("/profile/scheme/register/", "PUT", {username: this.state.profile.username, scheme_type: this.state.module, scheme_name: this.state.name})
      .then((res) => {
      })
      .fail((err) => {
        if (err.status === 401) {
          this.setState({registration: i18next.t("profile.scheme-webauthn-register-status-not-registered"), registered: false});
        } else {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-connect")});
        }
      });
    }
  }
  
  register() {
    apiManager.glewlwydRequest("/profile/scheme/register/", "POST", 
    {
      username: this.state.profile.username, 
      scheme_type: this.state.module, 
      scheme_name: this.state.name, 
      value: {
        register: "new-credential"
      }
    })
    .then((result) => {
      var createCredentialDefaultArgs = {
        publicKey: {
          authenticatorSelection: {
            requireResidentKey: false
          },
              
          rp: {
            name: result["rp-origin"]
          },
          
          authenticatorSelection: {
            requireResidentKey: false
          },

          user: {
            id: Uint8Array.from(atob(result.user.id), c => c.charCodeAt(0)),
            name: result.user.name,
            displayName: this.state.profile.name||result.user.name
          },

          pubKeyCredParams: result["pubKey-cred-params"],

          attestation: "direct",

          timeout: 60000,

          challenge: this.strToBin(result.challenge)
        }
      };

      navigator.credentials.create(createCredentialDefaultArgs)
      .then((cred) => {
        this.setState({status: "registered"});
        
        const publicKeyCredential = {};

        if ('id' in cred) {
          publicKeyCredential.id = cred.id;
        }
        if ('type' in cred) {
          publicKeyCredential.type = cred.type;
        }
        if ('rawId' in cred) {
          publicKeyCredential.rawId = this.binToStr(cred.rawId);
        }
        if (!cred.response) {
          console.log("Make Credential response lacking 'response' attribute");
        }

        const response = {};
        response.clientDataJSON = this.binToStr(cred.response.clientDataJSON);
        response.attestationObject = this.binToStr(cred.response.attestationObject);

        // Check if transports are included in the registration response.
        if (cred.response.getTransports) {
          response.transports = cred.response.getTransports();
        }

        publicKeyCredential.response = response;
        apiManager.glewlwydRequest("/profile/scheme/register/", "POST", {
          username: this.state.profile.username, 
          scheme_type: this.state.module, 
          scheme_name: this.state.name, 
          value: {
            register: "register-credential", 
            session: result.session, 
            credential: publicKeyCredential
          }
        })
        .then(() => {
          messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("profile.scheme-webauthn-register-credential-success")});
        })
        .fail((err) => {
          if (err.status === 400) {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.scheme-webauthn-register-credential-error")});
          } else {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-connect")});
          }
        });
      })
      .catch((err) => {
        console.log(err);
        this.setState({status: "error registration"});
      });
    })
    .fail((err) => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-connect")});
    })
    .always(() => {
      this.getRegister();
    });
  }
  
  testRegistration(e) {
    apiManager.glewlwydRequest("/auth/scheme/trigger/", "POST", 
    {
      username: this.state.profile.username, 
      scheme_type: this.state.module, 
      scheme_name: this.state.name, 
      value: {}
    })
    .then((result) => {
      // sample arguments for login
      var getCredentialDefaultArgs = {
        publicKey: {
          timeout: 60000,
          // allowCredentials: [newCredential] // see below
          challenge: new Uint8Array(atob(result.challenge)).buffer
        },
      };
      
      getCredentialDefaultArgs.publicKey.allowCredentials = this.state.idList;
      navigator.credentials.get(getCredentialDefaultArgs)
      .then((assertion) => {
        this.setState({status: "validated"});
      })
      .catch((err) => {
        this.setState({status: "error validation"});
      });
    })
    .fail((err) => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-connect")});
    })
    .always(() => {
      this.getRegister();
    });
  }
  
	render() {
    return (
      <div>
        <div className="row">
          <div className="col-md-12">
            <h4>{i18next.t("profile.scheme-webauthn-title", {module: this.state.module, name: this.state.name})}</h4>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12">
            {this.state.status}
          </div>
        </div>
        <div className="row">
          <div className="col-md-12">
            <hr/>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12">
            <div className="btn-group" role="group">
              <button type="button" className="btn btn-primary" onClick={(e) => this.register(e)}>{i18next.t("profile.scheme-webauthn-register")}</button>
              <button type="button" className="btn btn-primary" onClick={(e) => this.testRegistration(e)}>{i18next.t("profile.scheme-webauthn-test-registration")}</button>
            </div>
          </div>
        </div>
      </div>
    );
  }
}

export default SchemeWebauthn;
