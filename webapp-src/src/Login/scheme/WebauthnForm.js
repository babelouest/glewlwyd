import React, { Component } from 'react';

import apiManager from '../../lib/APIManager';
import messageDispatcher from '../../lib/MessageDispatcher';

class WebauthnForm extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      scheme: props.scheme,
      currentUser: props.currentUser,
      canLogin: false
    };
    
    this.triggerScheme = this.triggerScheme.bind(this);
    this.login = this.login.bind(this);
    
    this.triggerScheme();
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      scheme: nextProps.scheme,
      currentUser: nextProps.currentUser
    }, () => {
      this.triggerScheme();
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
  
  login(e) {
    apiManager.glewlwydRequest("/auth/scheme/trigger/", "POST", 
    {
      username: this.state.currentUser.username, 
      scheme_type: this.state.scheme.scheme_type,
      scheme_name: this.state.scheme.scheme_name,
      value: {}
    })
    .then((result) => {
      var allowCredentials = [];
      result.allowCredentials.forEach((cred) => {
        allowCredentials.push({
          id: this.strToBin(cred.credential_id),
          type: "public-key"
        });
      });
      
      var assertionRequest = {
        allowCredentials: allowCredentials,
        challenge: this.strToBin(result.challenge)
      };
      
      navigator.credentials.get({"publicKey": assertionRequest})
      .then((assertion) => {
        
        const publicKeyCredential = {};

        if ('id' in assertion) {
          publicKeyCredential.id = assertion.id;
        }
        if ('type' in assertion) {
          publicKeyCredential.type = assertion.type;
        }
        if ('rawId' in assertion) {
          publicKeyCredential.rawId = this.binToStr(assertion.rawId);
        }
        
        publicKeyCredential.response = {
          clientDataJSON: this.binToStr(assertion.response.clientDataJSON),
          authenticatorData: this.binToStr(assertion.response.authenticatorData),
          signature: this.binToStr(assertion.response.signature),
          userHandle: this.binToStr(assertion.response.userHandle)
        };

        // Check if transports are included in the registration response.
        if (assertion.response.getTransports) {
          response.transports = assertion.response.getTransports();
        }

        apiManager.glewlwydRequest("/auth/", "POST", 
        {
          username: this.state.currentUser.username, 
          scheme_type: this.state.scheme.scheme_type,
          scheme_name: this.state.scheme.scheme_name,
          value: {
            session: result.session, 
            credential: publicKeyCredential
          }
        })
        .then(() => {
          messageDispatcher.sendMessage('App', {type: 'loginSuccess'});
          messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("profile.scheme-webauthn-assertion-success")});
        })
        .fail((err) => {
          if (err.status === 401) {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.scheme-webauthn-assertion-error")});
          } else {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
          }
        });
      })
      .catch((err) => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.scheme-webauthn-error-assertion")});
      });
    })
    .fail((err) => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
    });
  }

  triggerScheme() {
    if (this.state.scheme && this.state.currentUser) {
      var scheme = {
        scheme_type: this.state.scheme.scheme_type,
        scheme_name: this.state.scheme.scheme_name,
        username: this.state.currentUser.username,
        value: {
        }
      };
      
      apiManager.glewlwydRequest("/auth/scheme/trigger/", "POST", scheme)
      .then((res) => {
        this.setState({canLogin: true});
      })
      .fail((err) => {
        this.setState({canLogin: false}, () => {
          if (err.status === 401) {
            messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("login.webauthn-trigger-must-register")});
          } else {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.webauthn-error-trigger")});
          }
        });
      });
    }
  }
  
  render() {
    return (
      <div>
        <div className="form-group">
          <h5>{i18next.t("login.webauthn-login-title")}</h5>
        </div>
        <div className="form-group">
        </div>
        <button type="button" name="loginBut" id="loginBut" disabled={!this.state.canLogin} className="btn btn-primary" onClick={(e) => this.login(e)} title={i18next.t("login.webauthn-login-button-title")}>{i18next.t("login.webauthn-login-authenticate")}</button>
      </div>
    );
  }
}

export default WebauthnForm;
