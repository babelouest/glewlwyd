import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';

class SchemeOauth2 extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      module: props.module,
      name: props.name,
      profile: props.profile,
      registerList: [],
      registerUrl: (props.config.params.register?"/" + props.config.params.register + "/profile":"/profile"),
      removeProvdier: false
    };
    
    this.getRegister = this.getRegister.bind(this);
    this.confirmRemoveRegistration = this.confirmRemoveRegistration.bind(this);
    
    this.getRegister();
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      module: nextProps.module,
      name: nextProps.name,
      profile: nextProps.profile,
      registerUrl: (nextProps.config.params.register?"/" + nextProps.config.params.register + "/profile":"/profile")
    }, () => {
      this.getRegister();
    });
  }
  
  getRegister() {
    if (this.state.profile) {
      apiManager.glewlwydRequest(this.state.registerUrl+"/scheme/register/", "PUT", {username: this.state.profile.username, scheme_type: this.state.module, scheme_name: this.state.name}, true)
      .then((res) => {
        this.setState({registerList: res});
      })
      .fail((err) => {
        if (err.status === 400) {
        } else {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
        }
      });
    }
  }
  
  addRegistration(provider) {
    if (this.state.profile) {
      apiManager.glewlwydRequest(this.state.registerUrl+"/scheme/register/", "POST", {username: this.state.profile.username, scheme_type: this.state.module, scheme_name: this.state.name, value: {provider: provider, action: "new", register_url: apiManager.getConfig(), complete_url: window.location.href}}, true)
      .then((res) => {
        document.location = res.redirect_to;
      })
      .fail((err) => {
        if (err.status === 400) {
        } else {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
        }
      });
    }
  }
  
  removeRegistration(provider) {
    this.setState({removeProvdier: provider}, () => {
      messageDispatcher.sendMessage('App', {
        type: 'confirm',
        title: i18next.t("profile.scheme-oauth2-confirm-title"), 
        message: i18next.t("profile.scheme-oauth2-confirm-message", {provider: provider}),
        callback: this.confirmRemoveRegistration
      });
    });
  }
  
  confirmRemoveRegistration(provider) {
    if (this.state.profile) {
      apiManager.glewlwydRequest(this.state.registerUrl+"/scheme/register/", "POST", {username: this.state.profile.username, scheme_type: this.state.module, scheme_name: this.state.name, value: {provider: this.state.removeProvdier, action: "delete"}}, true)
      .then((res) => {
        this.getRegister();
      })
      .fail((err) => {
        if (err.status === 400) {
        } else {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
        }
      })
      .always(() => {
        messageDispatcher.sendMessage('App', {type: 'closeConfirm'});
      });
    } else {
      messageDispatcher.sendMessage('App', {type: 'closeConfirm'});
    }
  }
  
	render() {
    var registerList = [];
    this.state.registerList.forEach((register, index) => {
      var logo, createdAt, lastSession, regButton;
      if (register.logo_uri) {
        logo = <img src={register.logo_uri} alt={register.provider} className="img-fluid logo-img" />
      } else if (register.logo_fa) {
        logo = <i className={register.logo_fa}></i>
      }
      if (register.created_at !== null) {
        createdAt = (new Date(register.created_at*1000)).toLocaleString();
        if (register.last_session) {
          lastSession = (new Date(register.last_session*1000)).toLocaleString();
        } else {
          lastSession = i18next.t("profile.scheme-oauth2-registration-invalid");
        }
        regButton = 
        <button type="button" className="btn btn-primary" onClick={(e) => this.removeRegistration(register.provider)} title={i18next.t("profile.scheme-oauth2-btn-remove")}>
          <i className="fas fa-trash"></i>
        </button>;
      } else {
        regButton = 
        <button type="button" className="btn btn-primary" onClick={(e) => this.addRegistration(register.provider)} title={i18next.t("profile.scheme-oauth2-btn-add")}>
          <i className="fas fa-plus"></i>
        </button>;
      }
      registerList.push(
        <tr key={index}>
          <td>
            {logo}
          </td>
          <td>
            <span className="badge badge-success">
              {register.provider}
            </span>
          </td>
          <td>
            {createdAt}
          </td>
          <td>
            {lastSession}
          </td>
          <td>
            {regButton}
          </td>
        </tr>
      );
    });
    return (
      <div>
        <div className="row">
          <div className="col-md-12">
            <h4>{i18next.t("profile.scheme-oauth2-title")}</h4>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12">
            <table className="table table-responsive table-striped">
              <thead>
                <tr>
                  <th>
                  </th>
                  <th>
                    {i18next.t("profile.scheme-oauth2-table-name")}
                  </th>
                  <th>
                    {i18next.t("profile.scheme-oauth2-table-created_at")}
                  </th>
                  <th>
                    {i18next.t("profile.scheme-oauth2-table-last_session")}
                  </th>
                  <th>
                  </th>
                </tr>
              </thead>
              <tbody>
                {registerList}
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
            </div>
          </div>
        </div>
      </div>
    );
  }
}

export default SchemeOauth2;
