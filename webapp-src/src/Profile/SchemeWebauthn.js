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
      credentialList: [],
      editIndex: -1,
      editValue: "",
      removeIndex: -1
    };
    
    this.getRegister = this.getRegister.bind(this);
    this.register = this.register.bind(this);
    this.testRegistration = this.testRegistration.bind(this);
    this.editNameCred = this.editNameCred.bind(this);
    this.changeName = this.changeName.bind(this);
    this.saveName = this.saveName.bind(this);
    this.cancelSaveName = this.cancelSaveName.bind(this);
    this.switchCred = this.switchCred.bind(this);
    this.removeCred = this.removeCred.bind(this);
    this.confirmRemoveCred = this.confirmRemoveCred.bind(this);
    
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
        this.setState({credentialList: res});
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
      
      var excludeCredentials = [];
      this.state.credentialList.forEach((cred) => {
        excludeCredentials.push({
          id: this.strToBin(cred.credential_id),
          type: "public-key"
        });
      });
      
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

          challenge: this.strToBin(result.challenge),
          
          excludeCredentials: excludeCredentials
        }
      };

      navigator.credentials.create(createCredentialDefaultArgs)
      .then((cred) => {
        
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
        })
        .always(() => {
          this.getRegister();
        });
      })
      .catch((err) => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.scheme-webauthn-error-registration")});
      });
    })
    .fail((err) => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-connect")});
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
      var allowCredentials = [];
      result.credentials.forEach((cred) => {
        allowCredentials.push({
          id: this.strToBin(cred.credential_id),
          type: "public-key"
        });
      });
      
      var getCredentialDefaultArgs = {
        rp: {
          name: result.user["rp-origin"]
        },
        
        publicKey: {
          timeout: 60000,
          allowCredentials: allowCredentials,
          challenge: this.strToBin(result.challenge)
        }
      };
      
      navigator.credentials.get(getCredentialDefaultArgs)
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
        if (!assertion.response) {
          console.log("Get assertion response lacking 'response' attribute");
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
          username: this.state.profile.username, 
          scheme_type: this.state.module, 
          scheme_name: this.state.name, 
          value: {
            session: result.session, 
            credential: publicKeyCredential
          }
        })
        .then(() => {
          messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("profile.scheme-webauthn-assertion-success")});
        })
        .fail((err) => {
          if (err.status === 401) {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.scheme-webauthn-assertion-error")});
          } else {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-connect")});
          }
        });
      })
      .catch((err) => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.scheme-webauthn-error-assertion")});
      });
    })
    .fail((err) => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-connect")});
    })
    .always(() => {
      this.getRegister();
    });
  }
  
  editNameCred(index) {
    this.setState({editIndex: index, editValue: this.state.credentialList[index].name});
  }
  
  changeName(e) {
    this.setState({editValue: e.target.value});
  }
  
  saveName(e, index) {
    e.preventDefault();
    
    apiManager.glewlwydRequest("/profile/scheme/register/", "POST", 
      {
        username: this.state.profile.username, 
        scheme_type: this.state.module, 
        scheme_name: this.state.name,
        value: {
          register: "edit-credential",
          credential_id: this.state.credentialList[index].credential_id,
          name: this.state.editValue
        }
      })
    .then((res) => {
      this.setState({editIndex: -1, editValue: ""}, () => {
        this.getRegister();
      });
    })
    .fail((err) => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-connect")});
    });
  }
  
  cancelSaveName() {
    this.setState({editIndex: -1, editValue: ""});
  }
  
  switchCred(index) {
    apiManager.glewlwydRequest("/profile/scheme/register/", "POST", 
      {
        username: this.state.profile.username, 
        scheme_type: this.state.module, 
        scheme_name: this.state.name,
        value: {
          register: (this.state.credentialList[index].status==="registered"?"disable-credential":"enable-credential"),
          credential_id: this.state.credentialList[index].credential_id
        }
      })
    .then((res) => {
      this.getRegister();
    })
    .fail((err) => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-connect")});
    });
  }

  removeCred(index) {
    this.setState({removeIndex: index}, () => {
      messageDispatcher.sendMessage('App', {
        type: 'confirm',
        title: i18next.t("profile.scheme-webauthn-confirm-title"), 
        message: i18next.t("profile.scheme-webauthn-confirm-message"),
        callback: this.confirmRemoveCred
      });
    });
  }
  
  confirmRemoveCred(result) {
    if (result) {
      apiManager.glewlwydRequest("/profile/scheme/register/", "POST", 
        {
          username: this.state.profile.username, 
          scheme_type: this.state.module, 
          scheme_name: this.state.name,
          value: {
            register: "remove-credential",
            credential_id: this.state.credentialList[this.state.removeIndex].credential_id
          }
        })
      .then((res) => {
        this.getRegister();
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.scheme-webauthn-removed")});
      })
      .fail((err) => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-connect")});
      })
      .always(() => {
        messageDispatcher.sendMessage('App', {type: 'closeConfirm'});
      });
    } else {
      messageDispatcher.sendMessage('App', {type: 'closeConfirm'});
    }
  }
  
	render() {
    var credentialList = [];
    this.state.credentialList.forEach((cred, index) => {
      if (this.state.editIndex === index) {
        credentialList.push(
          <tr key={index}>
            <td>
              {cred.created_at}
            </td>
            <td>
              <form className="needs-validation" noValidate onSubmit={(e) => this.saveName(e, index)}>
                <input type="text" className="form-control" value={this.state.editValue} onChange={(e) => this.changeName(e, index)} placeholder={i18next.t("profile.webauthn-edit-placeholder")} />
              </form>
            </td>
            <td>
              {i18next.t("admin.yes")}
            </td>
            <td>
              <div className="btn-group" role="group">
                <button type="button" className="btn btn-primary" onClick={(e) => this.saveName(e, index)} title={i18next.t("modal.ok")}>
                  <i className="fas fa-save"></i>
                </button>
                <button type="button" className="btn btn-primary" onClick={(e) => this.cancelSaveName()} title={i18next.t("modal.close")}>
                  <i className="fas fa-times"></i>
                </button>
              </div>
            </td>
          </tr>
        );
      } else if (cred.status === "registered") {
        credentialList.push(
          <tr key={index}>
            <td>
              {cred.created_at}
            </td>
            <td>
              <span className="badge badge-success">
                {cred.name}
              </span>
            </td>
            <td>
              {i18next.t("admin.yes")}
            </td>
            <td>
              <div className="btn-group" role="group">
                <button type="button" className="btn btn-primary" onClick={(e) => this.switchCred(index)} title={i18next.t("profile.scheme-webauthn-btn-switch-off")}>
                  <i className="fas fa-toggle-on"></i>
                </button>
                <button type="button" className="btn btn-primary" onClick={(e) => this.editNameCred(index)} title={i18next.t("profile.scheme-webauthn-btn-edit")}>
                  <i className="fas fa-edit"></i>
                </button>
                <button type="button" className="btn btn-primary" onClick={(e) => this.removeCred(index)} title={i18next.t("profile.scheme-webauthn-btn-remove")}>
                  <i className="fas fa-trash"></i>
                </button>
              </div>
            </td>
          </tr>
        );
      } else {
        credentialList.push(
          <tr key={index}>
            <td>
              {cred.created_at}
            </td>
            <td>
              <span className="badge badge-danger">
                {cred.name}
              </span>
            </td>
            <td>
              {i18next.t("admin.no")}
            </td>
            <td>
              <div className="btn-group" role="group">
                <button type="button" className="btn btn-primary" onClick={(e) => this.switchCred(index)} title={i18next.t("profile.scheme-webauthn-btn-switch-on")}>
                  <i className="fas fa-toggle-off"></i>
                </button>
                <button type="button" className="btn btn-primary" onClick={(e) => this.editNameCred(index)} title={i18next.t("profile.scheme-webauthn-btn-edit")}>
                  <i className="fas fa-edit"></i>
                </button>
                <button type="button" className="btn btn-primary" onClick={(e) => this.removeCred(index)} title={i18next.t("profile.scheme-webauthn-btn-remove")}>
                  <i className="fas fa-trash"></i>
                </button>
              </div>
            </td>
          </tr>
        );
      }
    });
    return (
      <div>
        <div className="row">
          <div className="col-md-12">
            <h4>{i18next.t("profile.scheme-webauthn-title", {module: this.state.module, name: this.state.name})}</h4>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12">
            <table className="table table-responsive table-striped">
              <thead>
                <tr>
                  <th>
                    {i18next.t("profile.scheme-webauthn-table-created_at")}
                  </th>
                  <th>
                    {i18next.t("profile.scheme-webauthn-table-name")}
                  </th>
                  <th>
                    {i18next.t("profile.scheme-webauthn-table-enabled")}
                  </th>
                  <th>
                  </th>
                </tr>
              </thead>
              <tbody>
                {credentialList}
              </tbody>
            </table>
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
