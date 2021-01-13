import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../../lib/APIManager';
import messageDispatcher from '../../lib/MessageDispatcher';

class MockSchemeForm extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      scheme: props.scheme,
      identify: props.identify,
      identifyUsername: "",
      currentUser: props.currentUser,
      triggerResult: false,
      mockValue: ""
    };
    
    this.triggerScheme = this.triggerScheme.bind(this);
    this.validateMockValue = this.validateMockValue.bind(this);
    this.handleChangeMockValue = this.handleChangeMockValue.bind(this);
    this.handleChangeIdentifyUsernameValue = this.handleChangeIdentifyUsernameValue.bind(this);
    
    this.triggerScheme();
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      scheme: nextProps.scheme,
      identify: nextProps.identify,
      identifyUsername: "",
      currentUser: nextProps.currentUser,
      triggerResult: false,
      mockValue: ""
    }, () => {
      this.triggerScheme();
    });
  }
  
  triggerScheme() {
    if (this.state.scheme) {
      if (this.state.currentUser.username) {
        var scheme = {
          scheme_type: this.state.scheme.scheme_type,
          scheme_name: this.state.scheme.scheme_name,
          username: this.state.currentUser.username,
          value: {
            description: "This is a mock trigger"
          }
        };
      } else {
        var scheme = {
          scheme_type: this.state.scheme.scheme_type,
          scheme_name: this.state.scheme.scheme_name,
          value: {
            description: "This is a mock trigger"
          }
        };
      }
      apiManager.glewlwydRequest("/auth/scheme/trigger/", "POST", scheme, true)
      .then((res) => {
        this.setState({triggerResult: res.code});
      })
      .fail((err) => {
        if (err.status === 401) {
          messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("login.mock-trigger-must-register")});
        } else {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-mock-trigger")});
        }
      });
    }
  }
  
  handleChangeMockValue(e) {
    this.setState({mockValue: e.target.value});
  }
  
  
  handleChangeIdentifyUsernameValue(e) {
    this.setState({identifyUsername: e.target.value});
  }
  
  validateMockValue(e) {
    e.preventDefault();
		var scheme = {
      scheme_type: this.state.scheme.scheme_type,
      scheme_name: this.state.scheme.scheme_name,
      username: this.state.currentUser.username,
			value: {
				code: this.state.mockValue
			}
		};
    if (!this.state.currentUser.username) {
      scheme.value.username = this.state.identifyUsername;
    }
    
    apiManager.glewlwydRequest("/auth/", "POST", scheme)
    .then(() => {
      messageDispatcher.sendMessage('App', {type: 'loginSuccess', loginSuccess: true});
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-mock-value")});
    });
  }
  
  render() {
    if (this.state.triggerResult) {
      var usernameJsx;
      if (!this.state.currentUser.username) {
        usernameJsx =
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="identifyUsername">{i18next.t("login.login")}</label>
              </div>
              <input type="text" 
                     className="form-control" 
                     name="identifyUsername" 
                     id="identifyUsername" 
                     autoFocus={true} 
                     required="" 
                     placeholder={i18next.t("login.login-placeholder")} 
                     value={this.state.identifyUsername||""} 
                     onChange={this.handleChangeIdentifyUsernameValue} 
                     autoComplete="false"/>
            </div>
          </div>
      }
      return (
        <form action="#" id="mockSchemeForm">
          <div className="form-group">
            <h5>{i18next.t("login.enter-mock-scheme-value")}</h5>
          </div>
          {usernameJsx}
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="mockValue">{i18next.t("login.mock-value-label")}</label>
              </div>
              <input type="text" 
                     className="form-control" 
                     name="mockValue" 
                     id="mockValue" 
                     autoFocus={true} 
                     required="" 
                     placeholder={i18next.t("login.error-mock-expected", {value: (this.state.triggerResult)})} 
                     value={this.state.mockValue||""} 
                     onChange={this.handleChangeMockValue} 
                     autoComplete="false"/>
            </div>
          </div>
          <button type="submit" 
                  name="mockbut" 
                  id="mockbut" 
                  className="btn btn-primary" 
                  onClick={(e) => this.validateMockValue(e)} 
                  title={i18next.t("login.mock-value-button-title")}>
            {i18next.t("login.btn-ok")}
          </button>
        </form>
      );
    } else {
      return (<button type="button" className="btn btn-primary" onClick={this.triggerScheme}>{i18next.t("login.btn-reload")}</button>);
    }
  }
}

export default MockSchemeForm;
