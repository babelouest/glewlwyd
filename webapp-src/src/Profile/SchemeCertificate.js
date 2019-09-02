import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';

class SchemeCertificate extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      module: props.module,
      name: props.name,
      profile: props.profile,
      registered: false,
      registration: false,
      certificateList: [],
      addModal: false,
      certFile: false,
      curCert: false,
      fileName: false
    };
    
    this.getRegister = this.getRegister.bind(this);
    this.selectCertFile = this.selectCertFile.bind(this);
    this.addCertificateFile = this.addCertificateFile.bind(this);
    this.addCertificateFromRequest = this.addCertificateFromRequest.bind(this);
    this.switchCertStatus = this.switchCertStatus.bind(this);
    this.deleteCert = this.deleteCert.bind(this);
    this.confirmDeleteCert = this.confirmDeleteCert.bind(this);
    
    this.getRegister();
  }

  UNSAFE_componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      module: nextProps.module,
      name: nextProps.name,
      profile: nextProps.profile,
      registered: false,
      registration: false,
      addModal: false,
      certFile: false,
      fileName: false
    });
  }
  
  getRegister() {
    if (this.state.profile) {
      apiManager.glewlwydRequest("/profile/scheme/register/", "PUT", {username: this.state.profile.username, scheme_type: this.state.module, scheme_name: this.state.name})
      .then((res) => {
        this.setState({certificateList: res, certFile: false, fileName: false});
      })
      .fail((err) => {
        this.setState({certificateList: [], certFile: false, fileName: false}, () => {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
        });
      });
    }
  }
  
  selectCertFile(e) {
    var profile = this.state.profile;
    var file = e.target.files[0];
    var fr = new FileReader();
    fr.onload = (ev2) => {
      this.setState({certFile: ev2.target.result, fileName: file.name});
    };
    fr.readAsText(file);
  }
  
  addCertificateFile() {
    if (this.state.certFile) {
      apiManager.glewlwydRequest("/profile/scheme/register/", "POST", {username: this.state.profile.username, scheme_type: this.state.module, scheme_name: this.state.name, value: {register: "upload-certificate", x509: this.state.certFile}})
      .then((res) => {
        this.getRegister();
      })
      .fail((err) => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
      });
    }
  }
  
  addCertificateFromRequest() {
    apiManager.glewlwydRequest("/profile/scheme/register/", "POST", {username: this.state.profile.username, scheme_type: this.state.module, scheme_name: this.state.name, value: {register: "use-certificate"}})
    .then((res) => {
      this.getRegister();
    })
    .fail((err) => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
    });
  }
  
  switchCertStatus(cert) {
    apiManager.glewlwydRequest("/profile/scheme/register/", "POST", {username: this.state.profile.username, scheme_type: this.state.module, scheme_name: this.state.name, value: {register: "toggle-certificate", certificate_id: cert.certificate_id, enabled: !cert.enabled}})
    .then((res) => {
      messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("profile.scheme-certificate-" + (cert.enabled?"disabled":"enabled"))});
      this.getRegister();
    })
    .fail((err) => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
    });
  }
  
  deleteCert(e, cert) {
    e.preventDefault();
    this.setState({curCert: cert, certFile: false, fileName: false}, () => {
      messageDispatcher.sendMessage('App', {
        type: 'confirm',
        title: i18next.t("profile.scheme-certificate-confirm-title"), 
        message: i18next.t("profile.scheme-certificate-confirm-message"),
        callback: this.confirmDeleteCert
      });
    });
  }
  
  confirmDeleteCert() {
    apiManager.glewlwydRequest("/profile/scheme/register/", "POST", {username: this.state.profile.username, scheme_type: this.state.module, scheme_name: this.state.name, value: {register: "delete-certificate", certificate_id: this.state.curCert.certificate_id}})
    .then((res) => {
      this.getRegister();
    })
    .fail((err) => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
    })
    .always(() => {
      messageDispatcher.sendMessage('App', {type: 'closeConfirm'});
    });
  }
  
	render() {
    var certificateList = [];
    this.state.certificateList.forEach((cert, index) => {
      var expiration = new Date(cert.expires_at * 1000), lastUsed = new Date(cert.last_used * 1000);
      var buttons;
      if (cert.enabled === true) {
        buttons = 
        <div className="btn-group" role="group">
          <button type="button" className="btn btn-secondary" onClick={(e) => this.switchCertStatus(cert)} title={i18next.t("admin.switch-off")}>
            <i className="fas fa-toggle-on"></i>
          </button>
          <button type="button" className="btn btn-secondary" onClick={(e) => this.deleteCert(e, cert)} title={i18next.t("admin.delete")}>
            <i className="fas fa-trash"></i>
          </button>
        </div>
      } else if (cert.enabled === false) {
        buttons = 
        <div className="btn-group" role="group">
          <button type="button" className="btn btn-secondary" onClick={(e) => this.switchCertStatus(cert)} title={i18next.t("admin.switch-on")}>
            <i className="fas fa-toggle-off"></i>
          </button>
          <button type="button" className="btn btn-secondary" onClick={(e) => this.deleteCert(e, cert)} title={i18next.t("admin.delete")}>
            <i className="fas fa-trash"></i>
          </button>
        </div>
      } else {
        buttons = 
        <div className="btn-group" role="group">
          <button type="button" disabled={true} className="btn btn-secondary" title={i18next.t("admin.switch-off")}>
            <i className="fas fa-toggle-on"></i>
          </button>
          <button type="button" disabled={true} className="btn btn-secondary" title={i18next.t("admin.delete")}>
            <i className="fas fa-trash"></i>
          </button>
        </div>
      }
      certificateList.push(
        <tr key={index}>
          <td>
            <span className="d-inline-block" tabIndex="0" data-toggle="tooltip" title={cert.certificate_dn}>
              {cert.certificate_dn.substring(0, 8)}[...]
            </span>
          </td>
          <td>
            <span className="d-inline-block" tabIndex="1" data-toggle="tooltip" title={cert.certificate_issuer_dn}>
              {cert.certificate_issuer_dn.substring(0, 8)}[...]
            </span>
          </td>
          <td>
            {expiration.toLocaleString()}
          </td>
          <td>
            {lastUsed.toLocaleString()}
          </td>
          <td>
            {buttons}
          </td>
        </tr>
      );
    });
    return (
      <div>
        <div className="row">
          <div className="col-md-12">
            <h4>{i18next.t("profile.scheme-certificate-title", {module: this.state.module, name: this.state.name})}</h4>
          </div>
        </div>
        <div className="row">
          <div className="col-md-6">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <button className="btn btn-outline-secondary" type="button" id="addCertificateFromFile" title={i18next.t("profile.scheme-certificate-add-from-file")} onClick={this.addCertificateFile}>
                  {i18next.t("upload")}
                </button>
              </div>
              <div className="custom-file">
                <input type="file" className="custom-file-input" id="addCertificateFromFileInput" aria-describedby="addCertificateFromFile" onChange={(e) => this.selectCertFile(e)} />
                <label className="custom-file-label" htmlFor="addCertificateFromFile">
                  {this.state.fileName||i18next.t("browse")}
                </label>
              </div>
            </div>
          </div>
          <div className="col-md-6">
            <button type="button" className="btn btn-outline-secondary" onClick={this.addCertificateFromRequest} title={i18next.t("profile.scheme-certificate-add-from-request")}>
              <i className="fas fa-file-contract"></i>
            </button>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12">
            <table className="table table-responsive table-striped">
              <thead>
                <tr>
                  <th>
                    {i18next.t("profile.scheme-certificate-table-certificate_dn")}
                  </th>
                  <th>
                    {i18next.t("profile.scheme-certificate-table-certificate_issuer_dn")}
                  </th>
                  <th>
                    {i18next.t("profile.scheme-certificate-table-expiration")}
                  </th>
                  <th>
                    {i18next.t("profile.scheme-certificate-table-last_used")}
                  </th>
                  <th>
                  </th>
                </tr>
              </thead>
              <tbody>
                {certificateList}
              </tbody>
            </table>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12">
            <hr/>
          </div>
        </div>
      </div>
    );
  }
}

export default SchemeCertificate;
