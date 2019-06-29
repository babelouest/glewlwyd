import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';

class SchemeMock extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      module: props.module,
      name: props.name,
      profile: props.profile,
      registered: false,
      registration: false
    };
    
    this.getRegister = this.getRegister.bind(this);
    this.register = this.register.bind(this);
    
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
  
  getRegister() {
    if (this.state.profile) {
      apiManager.glewlwydRequest("/profile/scheme/register/", "PUT", {username: this.state.profile.username, scheme_type: this.state.module, scheme_name: this.state.name})
      .then((res) => {
        this.setState({registration: i18next.t("profile.scheme-mock-register-status-registered"), registered: true});
      })
      .fail((err) => {
        if (err.status === 401) {
          this.setState({registration: i18next.t("profile.scheme-mock-register-status-not-registered"), registered: false});
        } else {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
        }
      });
    }
  }
  
  register() {
    apiManager.glewlwydRequest("/profile/scheme/register/", "POST", {username: this.state.profile.username, scheme_type: this.state.module, scheme_name: this.state.name, value: {register: !this.state.registered}})
    .fail((err) => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
    })
    .always(() => {
      this.getRegister();
    });
  }
  
	render() {
    var registration;
    if (this.state.registration) {
      registration = <div><h4>{i18next.t("profile.scheme-mock-register-status")}</h4><span className="badge badge-primary">{this.state.registration}</span></div>;
    }
    return (
      <div>
        <div className="row">
          <div className="col-md-12">
            <h4>{i18next.t("profile.scheme-mock-title", {module: this.state.module, name: this.state.name})}</h4>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12">
            {registration}
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
              <button type="button" className="btn btn-primary" onClick={(e) => this.register(e)}>{this.state.registered?i18next.t("profile.scheme-mock-deregister"):i18next.t("profile.scheme-mock-register")}</button>
            </div>
          </div>
        </div>
      </div>
    );
  }
}

export default SchemeMock;
