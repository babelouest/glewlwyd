import React, { Component } from 'react';
import i18next from 'i18next';

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
      schemePrefix: props.schemePrefix,
      registered: false,
      registration: false,
      certificateList: [],
      dn: false,
      addModal: false,
      certFile: false,
      curCert: false,
      fileName: false,
      activeCert: false,
      downloadCert: false,
      canAddCert: false,
      canRequestCert: false,
      forbidden: false
    };
    
    this.getRegister = this.getRegister.bind(this);
    this.selectCertFile = this.selectCertFile.bind(this);
    this.addCertificateFile = this.addCertificateFile.bind(this);
    this.addCertificateFromRequest = this.addCertificateFromRequest.bind(this);
    this.switchCertStatus = this.switchCertStatus.bind(this);
    this.deleteCert = this.deleteCert.bind(this);
    this.confirmDeleteCert = this.confirmDeleteCert.bind(this);
    this.testCertificate = this.testCertificate.bind(this);
    
    this.getRegister();
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      module: nextProps.module,
      name: nextProps.name,
      profile: nextProps.profile,
      schemePrefix: nextProps.schemePrefix,
      registered: false,
      registration: false,
      certificateList: [],
      dn: false,
      addModal: false,
      certFile: false,
      fileName: false,
      activeCert: false,
      downloadCert: false,
      canAddCert: false,
      canRequestCert: false,
      forbidden: false
    }, () => {
      this.getRegister();
    });
  }
  
  getRegister() {
    if (this.state.profile) {
      return apiManager.glewlwydRequest(this.state.schemePrefix+"/scheme/register/", "PUT", {username: this.state.profile.username, scheme_type: this.state.module, scheme_name: this.state.name, forbidden: false})
      .then((res) => {
        this.setState({certificateList: res.certificate||[], dn: res.dn||false, canAddCert: res["add-certificate"], certFile: false, canRequestCert: res["request-certificate"], fileName: false, activeCert: false, downloadCert: false});
      })
      .fail((err) => {
        this.setState({certificateList: [], dn: false, canAddCert: false, canRequestCert: false, certFile: false, fileName: false, downloadCert: false, forbidden: err.status === 403}, () => {
          if (err.status !== 403 && err.status !== 401) {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
          }
        });
      });
    } else {
      return Promise.reject(new Error('fail'));
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
      apiManager.glewlwydRequest(this.state.schemePrefix+"/scheme/register/", "POST", {username: this.state.profile.username, scheme_type: this.state.module, scheme_name: this.state.name, value: {register: "upload-certificate", x509: this.state.certFile}})
      .then((res) => {
        this.getRegister();
        if (this.state.config.params.register) {
          messageDispatcher.sendMessage('App', {type: "registration"});
          messageDispatcher.sendMessage('App', {type: "nav", page: "profile"});
        }
      })
      .fail((err) => {
        if (err.status === 400) {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.scheme-certificate-invalid")});
        } else if (err.status === 401) {
          messageDispatcher.sendMessage('App', {type: "loggedIn", loggedIn: false});
        } else {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
        }
      });
    }
  }
  
  addCertificateFromRequest() {
    apiManager.glewlwydRequest(this.state.schemePrefix+"/scheme/register/", "POST", {username: this.state.profile.username, scheme_type: this.state.module, scheme_name: this.state.name, value: {register: "use-certificate"}})
    .then((res) => {
      this.getRegister();
      if (this.state.config.params.register) {
        messageDispatcher.sendMessage('App', {type: "registration"});
      }
    })
    .fail((err) => {
      if (err.status === 400) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.scheme-certificate-invalid")});
      } else if (err.status === 401) {
        messageDispatcher.sendMessage('App', {type: "loggedIn", loggedIn: false});
      } else {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
      }
    });
  }
  
  switchCertStatus(cert) {
    apiManager.glewlwydRequest(this.state.schemePrefix+"/scheme/register/", "POST", {username: this.state.profile.username, scheme_type: this.state.module, scheme_name: this.state.name, value: {register: "toggle-certificate", certificate_id: cert.certificate_id, enabled: !cert.enabled}})
    .then((res) => {
      messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("profile.scheme-certificate-" + (cert.enabled?"disabled":"enabled"))});
      this.getRegister();
      if (this.state.config.params.register) {
        messageDispatcher.sendMessage('App', {type: "registration"});
      }
    })
    .fail((err) => {
      if (err.status === 401) {
        messageDispatcher.sendMessage('App', {type: "loggedIn", loggedIn: false});
      } else {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
      }
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
  
  confirmDeleteCert(result) {
    if (result) {
      apiManager.glewlwydRequest(this.state.schemePrefix+"/scheme/register/", "POST", {username: this.state.profile.username, scheme_type: this.state.module, scheme_name: this.state.name, value: {register: "delete-certificate", certificate_id: this.state.curCert.certificate_id}})
      .then((res) => {
        this.getRegister();
        if (this.state.config.params.register) {
          messageDispatcher.sendMessage('App', {type: "registration"});
        }
      })
      .fail((err) => {
        if (err.status === 401) {
          messageDispatcher.sendMessage('App', {type: "loggedIn", loggedIn: false});
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
  
  testCertificate() {
    apiManager.glewlwydRequest(this.state.schemePrefix+"/scheme/register/", "POST", {username: this.state.profile.username, scheme_type: this.state.module, scheme_name: this.state.name, value: {register: "test-certificate"}})
    .then((res) => {
      this.setState({activeCert: res});
      messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("profile.scheme-certificate-test-valid")});
    })
    .fail((err) => {
      if (err.status === 400) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.scheme-certificate-invalid")});
      } else if (err.status === 401) {
        messageDispatcher.sendMessage('App', {type: "loggedIn", loggedIn: false});
      } else {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
      }
    });
  }
  
	render() {
    var certificateList = [], forbiddenJsx;
    this.state.certificateList.forEach((cert, index) => {
      var expiration = new Date(cert.expiration * 1000), lastUsed = new Date(cert.last_used * 1000);
      var buttons, checked;
      if (this.state.activeCert && cert.certificate_id === this.state.activeCert.certificate_id) {
        checked = <i className="far fa-check-circle btn-icon-right text-success"></i>;
      }
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
            {checked}
          </td>
          <td className="d-none d-lg-table-cell">
            <span className="d-inline-block" tabIndex="1" data-toggle="tooltip" title={cert.certificate_issuer_dn}>
              {cert.certificate_issuer_dn.substring(0, 8)}[...]
            </span>
          </td>
          <td className="d-none d-lg-table-cell">
            {expiration.toLocaleString()}
          </td>
          <td className="d-none d-lg-table-cell">
            {lastUsed.toLocaleString()}
          </td>
          <td>
            {buttons}
          </td>
        </tr>
      );
    });
    if (this.state.dn) {
      certificateList.push(
        <tr key={certificateList.length}>
          <td>
            <span className="d-inline-block" tabIndex="0" data-toggle="tooltip" title={this.state.dn}>
              {this.state.dn.substring(0, 8)}[...]
            </span>
          </td>
          <td className="d-none d-lg-table-cell">
            <span className="d-inline-block" tabIndex="1" data-toggle="tooltip">
            </span>
          </td>
          <td className="d-none d-lg-table-cell">
          </td>
          <td className="d-none d-lg-table-cell">
          </td>
          <td>
          </td>
        </tr>
      );
    }
    if (this.state.forbidden) {
      forbiddenJsx = <h4 className="alert alert-danger">{i18next.t("profile.scheme-register-forbidden")}</h4>;
    }
    return (
      <div>
        <div className="row">
          <div className="col-md-12">
            <h4>{i18next.t("profile.scheme-certificate-title", {module: this.state.module, name: this.state.name})}</h4>
          </div>
        </div>
        {forbiddenJsx}
        <div className="row">
          <div className="col-md-6">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <button className="btn btn-outline-secondary" type="button" disabled={!this.state.canAddCert||this.state.forbidden} id="addCertificateFromFile" title={i18next.t("profile.scheme-certificate-add-from-file")} onClick={this.addCertificateFile}>
                  {i18next.t("upload")}
                </button>
              </div>
              <div className="custom-file">
                <input type="file" disabled={!this.state.canAddCert||this.state.forbidden} className="custom-file-input" id="addCertificateFromFileInput" aria-describedby="addCertificateFromFile" onChange={(e) => this.selectCertFile(e)} />
                <label className="custom-file-label" htmlFor="addCertificateFromFile">
                  {this.state.fileName||i18next.t("browse")}
                </label>
              </div>
            </div>
          </div>
          <div className="col-md-6">
            <div className="btn-group" role="group" aria-label="current-certificate">
              <button type="button" className="btn btn-outline-secondary" disabled={!this.state.canAddCert||this.state.forbidden} onClick={this.addCertificateFromRequest} title={i18next.t("profile.scheme-certificate-add-from-request")}>
                <i className="fas fa-file-code-o"></i>
              </button>
              <button type="button" className="btn btn-outline-secondary" disabled={this.state.forbidden} onClick={this.testCertificate} title={i18next.t("profile.scheme-certificate-test")}>
                <i className="fas fa-question-circle"></i>
              </button>
              <button type="button" className="btn btn-outline-secondary" disabled={this.state.forbidden} onClick={this.getRegister} title={i18next.t("profile.scheme-certificate-refresh")}>
                <i className="fas fa-sync"></i>
              </button>
            </div>
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
                  <th className="d-none d-lg-table-cell">
                    {i18next.t("profile.scheme-certificate-table-certificate_issuer_dn")}
                  </th>
                  <th className="d-none d-lg-table-cell">
                    {i18next.t("profile.scheme-certificate-table-expiration")}
                  </th>
                  <th className="d-none d-lg-table-cell">
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
