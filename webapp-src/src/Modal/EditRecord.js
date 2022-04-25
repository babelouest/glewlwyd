import React, { Component } from 'react';
import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';

class EditRecord extends Component {
  constructor(props) {
    super(props);

    this.state = {
      title: props.title,
      pattern: props.pattern,
      source: props.source,
      defaultSource: props.defaultSource,
      data: props.data,
      cb: props.callback,
      validateCb: props.validateCallback,
      profile: props.profile,
      add: props.add,
      listAddValue: this.initListAdd(props.pattern, props.data),
      listEltConfirm: this.initListConfirm(props.pattern),
      listError: {},
      hasError: false,
      listPwd: this.initListPwd(props.pattern, props.data, props.add),
      multiplePasswords: this.hasMultiplePasswords(props.source, props.data)
    }

    this.closeModal = this.closeModal.bind(this);
    this.changeSource = this.changeSource.bind(this);
    this.editElt = this.editElt.bind(this);
    this.changeElt = this.changeElt.bind(this);
    this.toggleBooleanElt = this.toggleBooleanElt.bind(this);
    this.deleteListElt = this.deleteListElt.bind(this);
    this.createData = this.createData.bind(this);
    this.changeListAddElt = this.changeListAddElt.bind(this);
    this.AddListElt = this.AddListElt.bind(this);
    this.initListAdd = this.initListAdd.bind(this);
    this.initListConfirm = this.initListConfirm.bind(this);
    this.initListPwd = this.initListPwd.bind(this);
    this.changeEltConfirm = this.changeEltConfirm.bind(this);
    this.changeTextArea = this.changeTextArea.bind(this);
    this.uploadFile = this.uploadFile.bind(this);
    this.uploadImage = this.uploadImage.bind(this);
    this.removeImage = this.removeImage.bind(this);
    this.setPwd = this.setPwd.bind(this);
    this.hasMultiplePasswords = this.hasMultiplePasswords.bind(this);
    this.exportRecord = this.exportRecord.bind(this);
    this.importRecord = this.importRecord.bind(this);
    this.getImportFile = this.getImportFile.bind(this);

    if (this.state.add) {
      this.createData();
    }
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      title: nextProps.title,
      pattern: nextProps.pattern,
      source: nextProps.source,
      defaultSource: nextProps.defaultSource,
      data: nextProps.data,
      cb: nextProps.callback,
      validateCb: nextProps.validateCallback,
      profile: nextProps.profile,
      add: nextProps.add,
      listAddValue: this.initListAdd(nextProps.pattern),
      listEltConfirm: this.initListConfirm(nextProps.pattern, nextProps.data),
      listError: {},
      hasError: false,
      listPwd: this.initListPwd(nextProps.pattern, nextProps.data, nextProps.add),
      multiplePasswords: this.hasMultiplePasswords(nextProps.source, nextProps.data)
    }, () => {
      if (nextProps.add) {
        this.createData();
      }
    });
  }

  closeModal(e, result) {
    if (this.state.cb) {
      if (result) {
        if (this.state.validateCb) {
          // Clean data of empty and unset values
          var data = this.state.data;
          for (var key in data) {
            if (Array.isArray(data[key]) && key !== "password") {
              if (!data[key].length) {
                delete(data[key]);
              } else {
                var arr = data[key];
                for (var i=arr.length-1; i>=0; i--) {
                  if (arr[i] === "") {
                    arr.splice(i, 1);
                  }
                }
              }
            }
          }
          var hasError = false, listError = [];
          for (var key in this.state.listAddValue) {
            if (this.state.listAddValue[key] !== "") {
              hasError = true;
              listError[key] = i18next.t("admin.add-elt-mandatory");
            }
          }
          if (!hasError) {
            this.state.validateCb(data, this.state.listEltConfirm, this.state.add, (res, errData) => {
              if (res) {
                this.state.cb(result, data);
              } else {
                this.setState({listError: errData, hasError: true});
              }
            });
          } else {
            this.setState({listError: listError, hasError: true});
          }
        } else {
          this.state.cb(result, data);
        }
      } else {
        this.state.cb(result, {});
      }
    }
  }

  changeSource(e, source) {
    var data = this.state.data;
    var listEltConfirm = this.state.listEltConfirm;
    var listPwd = this.state.listPwd;
    data.source = source;
    var multiplePasswords = false;
    for (var i=0; i<this.state.source.length; i++) {
      if (source === this.state.source[i].name) {
        multiplePasswords = this.state.source[i].multiple_passwords;
        if (multiplePasswords) {
          data.password = [""];
          listEltConfirm["password"] = [""];
          listPwd["password"] = ["set"];
        }
      }
    }
    this.setState({data: data, listEltConfirm: listEltConfirm, listPwd: listPwd, multiplePasswords: multiplePasswords});
  }

  editElt(pattern, elt, key) {
    var labelJsx, inputJsx, listJsx = [], checkboxJsx = false;
    if (elt !== undefined || pattern.type === "password" || pattern.forceShow) {
      if (!this.state.profile || pattern.profile) {
        var validInput = "";
        var errorJsx = "";
        if (this.state.listError[pattern.name]) {
          validInput = " is-invalid";
          errorJsx = <span className="error-input">{i18next.t(this.state.listError[pattern.name])}</span>
        }
        labelJsx = <label className="input-group-text" htmlFor={"modal-edit-" + pattern.name}>{i18next.t(pattern.label)}</label>;
        if (pattern.list) {
          if (!elt) {
            elt = [];
          }
          if (!pattern.listElements) {
            if (pattern.type === "textarea") {
              inputJsx = <textarea className={"form-control" + validInput} onChange={(e) => this.changeTextArea(e, pattern.name, true)} value={elt.join("\n")} placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""}></textarea>
            } else if (pattern.type === "file") {
              if (pattern.edit || this.state.add) {
                inputJsx = <input type="file" className={"form-control" + validInput} onChange={(e) => this.uploadFile(e, pattern.name, true)} />
              } else {
                inputJsx = <input type="file" disabled={true} className="form-control" />
              }
            } else if (pattern.type && pattern.type.startsWith("image")) {
              var img = [];
              elt.forEach((curElt, index) => {
                img.push(
                  <a key={index} href="#" onClick={(e) => this.removeImage(e, pattern.name, index)} title={i18next.t("remove")}>
                    <img className="btn-icon-right img-thumb" src={"data:"+pattern.type+";base64,"+curElt} alt={pattern.name+"-"+index} />
                    <span className="badge badge-secondary align-top">
                      <i className="fas fa-trash"></i>
                    </span>
                  </a>
                );
              });
              if (pattern.edit || this.state.add) {
                inputJsx =
                <div>
                  <div className="custom-file">
                    <input type="file" accept="image/*" className={"custom-file-input" + validInput} onChange={(e) => this.uploadImage(e, pattern.name, true)} id={"modal-image-" + pattern.name}/>
                    <label className="custom-file-label" htmlFor={"modal-image-" + pattern.name}>
                      {i18next.t("browse")}
                    </label>
                  </div>
                  {img}
                </div>
              } else {
                var img = [];
                elt.forEach((curElt, index) => {
                  img.push(
                    <img key={index} className="btn-icon-right img-thumb" src={"data:"+pattern.type+";base64,"+curElt} alt={pattern.name+"-"+index} />
                  );
                });
                inputJsx = img;
              }
            } else {
              inputJsx = <div className="input-group">
                <input type="text" className={"form-control" + validInput} id={"modal-edit-" + pattern.name} placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""} onChange={(e) => this.changeListAddElt(e, pattern.name)} value={this.state.listAddValue[pattern.name]||""} />
                <div className="input-group-append">
                  <button className="btn btn-outline-secondary" type="button" onClick={(e) => this.AddListElt(e, pattern.name)} title={i18next.t("modal.list-add-title")}>
                    <i className="fas fa-plus"></i>
                  </button>
                </div>
              </div>
            }
          } else {
            var listElements = [];
            pattern.listElements.forEach((element, index) => {
              listElements.push(<a className="dropdown-item" key={index} href="#" onClick={(e) => this.AddListElt(e, pattern.name, element)}>{element}</a>);
            });
            inputJsx = <div className="dropdown">
              <button className="btn btn-secondary dropdown-toggle" type="button" id={"modal-edit-" + pattern.name} data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                <i className="fas fa-plus"></i>
              </button>
              <div className="dropdown-menu" aria-labelledby={"modal-edit-" + pattern.name}>
                {listElements}
              </div>
            </div>
          }
          if ((pattern.type && pattern.type !== "textarea" && !pattern.type.startsWith("image")) || !pattern.type) {
            elt.forEach((val, index) => {
              var displayVal = val;
              if (pattern.type === "file") {
                displayVal = val.substring(0, val.indexOf("/"));
              }
              if (pattern.edit === false && !this.state.add) {
                listJsx.push(<span className="badge badge-primary btn-icon-right" key={index}>{displayVal}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span>);
              } else {
                listJsx.push(<a href="#" onClick={(e) => this.deleteListElt(e, pattern.name, index)} key={index}><span className="badge badge-primary btn-icon-right">{displayVal}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span></a>);
              }
            });
          }
        } else if (pattern.type === "boolean") {
          if (pattern.edit === false && !this.state.add) {
            checkboxJsx =
              <div className="form-group form-check" key={key}>
                <input disabled={true} type="checkbox" className="form-check-input" id={"modal-edit-" + pattern.name} checked={elt} />
                <label className="form-check-label" htmlFor={"modal-edit-" + pattern.name}>{i18next.t(pattern.label)}</label>
              </div>
          } else {
            checkboxJsx =
              <div className="form-group form-check" key={key}>
                <input type="checkbox" className={"form-check-input" + validInput} id={"modal-edit-" + pattern.name} onChange={(e) => this.toggleBooleanElt(e, pattern.name)} checked={elt} />
                <label className="form-check-label" htmlFor={"modal-edit-" + pattern.name}>{i18next.t(pattern.label)}</label>
              </div>
          }
        } else if (pattern.type === "textarea") {
          if (pattern.edit === false && !this.state.add) {
            inputJsx = <textarea className="form-control" disabled={true} value={elt||""}></textarea>
          } else {
            inputJsx = <textarea className={"form-control" + validInput} onChange={(e) => this.changeTextArea(e, pattern.name, false)} value={elt||""} placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""}></textarea>
          }
        } else if (pattern.type === "file") {
          if (elt) {
            listJsx.push(<a href="#" key={0} onClick={(e) => this.deleteFile(e, pattern.name, -1)}><span className="badge badge-primary btn-icon-right">{elt.substring(0, elt.indexOf("/"))}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span></a>);
          }
          if (pattern.edit || this.state.add) {
            inputJsx = <input type="file" className={"form-control" + validInput} onChange={(e) => this.uploadFile(e, pattern.name)} />
          } else {
            inputJsx = <input type="file" disabled={true} className="form-control" />
          }
        } else if (pattern.type && pattern.type.startsWith("image")) {
          var img;
          if (elt) {
            img = <a href="#" onClick={(e) => this.removeImage(e, pattern.name, -1)} title={i18next.t("remove")}>
              <img className="btn-icon-right img-thumb" src={"data:"+pattern.type+";base64,"+elt} alt={pattern.name} />
              <span className="badge badge-secondary align-top">
                <i className="fas fa-trash"></i>
              </span>
            </a>
          }
          if (pattern.edit || this.state.add) {
            inputJsx =
            <div>
              <div className="custom-file">
                <input type="file" accept="image/*" className={"custom-file-input" + validInput} onChange={(e) => this.uploadImage(e, pattern.name)} id={"modal-image-" + pattern.name} />
                <label className="custom-file-label" htmlFor={"modal-image-" + pattern.name}>
                  {i18next.t("browse")}
                </label>
              </div>
              {img}
            </div>
          } else {
            inputJsx = <img className="btn-icon-right img-thumb" src={"data:"+pattern.type+";base64,"+elt} alt={pattern.name} />;
          }
        } else {
          if (pattern.edit === false && !this.state.add) {
            inputJsx = <input disabled={true} type={(pattern.type||"text")} className={"form-control" + validInput} id={"modal-edit-" + pattern.name} placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""} value={elt||""}/>
          } else {
            if (pattern.listElements) {
              var listElements = [];
              pattern.listElements.forEach((element, index) => {
                listElements.push(<a className="dropdown-item" key={index} href="#" onClick={(e) => this.changeElt({target: {value: element}}, pattern.name)}>{i18next.t(element)}</a>);
              });
              inputJsx = <div className="dropdown">
                <button className="btn btn-secondary dropdown-toggle" type="button" id={"modal-edit-" + pattern.name} data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                  {i18next.t((elt?elt:"login.select"))}
                </button>
                <div className="dropdown-menu" aria-labelledby={"modal-edit-" + pattern.name}>
                  {listElements}
                </div>
              </div>
            } else if (pattern.type === "password") {
              if (!this.state.multiplePasswords) {
                var keepOption = "", valuePassword = "", valueConfirmPassword = "";
                if (!this.state.add) {
                  keepOption = <a className="dropdown-item" href="#" onClick={(e) => this.setPwd(e, pattern.name, "keep")}>{i18next.t("modal.pwd-keep")}</a>;
                }
                var pwdDropdown = <div className="dropdown">
                  <button className="btn btn-secondary dropdown-toggle" type="button" id={"modal-pwd-" + pattern.name} data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    {i18next.t("modal.pwd-" + (this.state.listPwd[pattern.name]||(this.state.add?"set":"keep")))}
                  </button>
                  <div className="dropdown-menu" aria-labelledby={"modal-pwd-" + pattern.name}>
                    {keepOption}
                    <a className="dropdown-item" href="#" onClick={(e) => this.setPwd(e, pattern.name, "set")}>{i18next.t("modal.pwd-set")}</a>
                    <a className="dropdown-item" href="#" onClick={(e) => this.setPwd(e, pattern.name, "disabled")}>{i18next.t("modal.pwd-disabled")}</a>
                  </div>
                </div>
                if (this.state.listPwd[pattern.name]==="set") {
                  valuePassword = elt||"";
                  valueConfirmPassword = this.state.listEltConfirm[pattern.name]||"";
                }
                inputJsx =
                  <div>
                    {pwdDropdown}
                    <input type="password"
                           autoComplete="new-password"
                           disabled={this.state.listPwd[pattern.name]!=="set"}
                           className={"form-control" + validInput}
                           id={"modal-edit-" + pattern.name}
                           placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""}
                           onChange={(e) => this.changeElt(e, pattern.name)}
                           value={valuePassword}/>
                    <input type="password"
                           autoComplete="new-password"
                           disabled={this.state.listPwd[pattern.name]!=="set"}
                           className={"form-control" + validInput}
                           id={"modal-edit-confirm" + pattern.name}
                           placeholder={i18next.t(pattern.placeholderConfirm)}
                           onChange={(e) => this.changeEltConfirm(e, pattern.name)}
                           value={valueConfirmPassword} />
                  </div>;
              } else {
                var pwdJsx = [], counter = 0;
                elt.forEach((curPassword, index) => {
                  if (curPassword !== null) {
                    counter++;
                    var curPasswordConfirm = this.state.listEltConfirm[pattern.name][index]||"";
                    if (this.state.listPwd[pattern.name][index]!=="set") {
                      curPassword = "";
                      curPasswordConfirm = "";
                    }
                    var keepOption = "";
                    if (!this.state.add) {
                      keepOption = <a className="dropdown-item" href="#" onClick={(e) => this.setPwd(e, pattern.name, "keep", index)}>{i18next.t("modal.pwd-keep")}</a>;
                    }
                    var pwdDropdown =
                    <div className="btn-group" role="group">
                      <div className="btn-group" role="group">
                        <div className="dropdown">
                          <button className="btn btn-secondary dropdown-toggle" type="button" id={"modal-pwd-" + pattern.name} data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                            <span className="badge badge-light btn-icon">
                              {counter}
                            </span>
                            {i18next.t("modal.pwd-" + (this.state.listPwd[pattern.name][index]))}
                          </button>
                          <div className="dropdown-menu" aria-labelledby={"modal-pwd-" + pattern.name}>
                            {keepOption}
                            <a className="dropdown-item" href="#" onClick={(e) => this.setPwd(e, pattern.name, "set", index)}>{i18next.t("modal.pwd-set")}</a>
                          </div>
                        </div>
                        <button className="btn btn-secondary" type="button" onClick={(e) => this.deletePasswordAt(pattern.name, index)} title={i18next.t("admin.delete")}>
                          <i className="fas fa-trash"></i>
                        </button>
                      </div>
                    </div>
                    pwdJsx.push(
                      <div key={index}>
                        {pwdDropdown}
                        <input type="password"
                               autoComplete="new-password"
                               disabled={this.state.listPwd[pattern.name][index]==="disabled"||this.state.listPwd[pattern.name][index]==="keep"}
                               className={"form-control" + validInput}
                               id={"modal-edit-" + pattern.name}
                               placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""}
                               onChange={(e) => this.changeElt(e, pattern.name, index)}
                               value={curPassword}/>
                        <input type="password"
                               autoComplete="new-password"
                               disabled={this.state.listPwd[pattern.name][index]==="disabled"||this.state.listPwd[pattern.name][index]==="keep"}
                               className={"form-control" + validInput}
                               id={"modal-edit-confirm" + pattern.name}
                               placeholder={i18next.t(pattern.placeholderConfirm)}
                               value={curPasswordConfirm}
                               onChange={(e) => this.changeEltConfirm(e, pattern.name, index)} />
                      </div>);
                  }
                });
                inputJsx =
                  <div className="card">
                    <div className="card-body">
                      {pwdJsx}
                      <hr/>
                      <button className="btn btn-secondary" type="button" onClick={(e) => this.addPassword(pattern.name)} title={i18next.t("admin.add")}>
                        <i className="fas fa-plus"></i>
                      </button>
                    </div>
                  </div>
              }
            } else if (pattern.type === "jwks") {
              inputJsx = <textarea className={"form-control" + validInput} id={"modal-edit-" + pattern.name} placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""} value={this.state.listEltConfirm[pattern.name]||""} onChange={(e) => this.setJwks(e, pattern.name)}></textarea>
            } else {
              inputJsx = <input type={(pattern.type||"text")} className={"form-control" + validInput} id={"modal-edit-" + pattern.name} placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""} value={elt||""} onChange={(e) => this.changeElt(e, pattern.name)} />
            }
          }
        }
      }
    }
    if (checkboxJsx) {
      return checkboxJsx;
    } else {
      return (
      <div className="form-group" key={key}>
        <div className="input-group mb-3">
          <div className="input-group-prepend">
            {labelJsx}
          </div>
          {inputJsx}
          <div className="btn-icon-right">{listJsx}</div>
        </div>
        {errorJsx}
      </div>);
    }
  }

  deleteListElt(e, name, index) {
    var data = this.state.data;
    if (data[name]) {
      data[name].splice(index, 1);
      this.setState({data: data});
    }
  }

  changeElt(e, name, index = -1) {
    var data = this.state.data;
    if (index >= 0) {
      if (data[name] === undefined) {
        data[name] = [];
      }
      data[name][index] = e.target.value;
    } else {
      data[name] = e.target.value;
    }
    this.setState({data: data});
  }

  changeEltConfirm(e, name, index = -1) {
    var listEltConfirm = this.state.listEltConfirm;
    if (index >= 0) {
      listEltConfirm[name][index] = e.target.value;
    } else {
      listEltConfirm[name] = e.target.value;
    }
    this.setState({listEltConfirm: listEltConfirm});
  }

  setJwks(e, name) {
    var data = this.state.data;
    var listError = this.state.listError;
    var hasError = this.state.hasError;
    var listEltConfirm = this.state.listEltConfirm;
    var value = e.target.value;
    listError[name] = false;
    hasError = false;
    if (value) {
      try {
        data[name] = JSON.parse(value);
      } catch (e) {
        listError[name] = i18next.t("admin.invalid-json");
        delete(data[name]);
        hasError = true;
      }
    }
    listEltConfirm[name] = value;
    this.setState({data: data, listEltConfirm: listEltConfirm, hasError: hasError});
  }

  toggleBooleanElt(e, name) {
    var data = this.state.data;
    data[name] = !data[name];
    this.setState({data: data});
  }

  createData() {
    var data = {
      source: this.state.defaultSource
    };
    this.state.pattern.forEach((pat, index) => {
      if (pat.list) {
        if (pat.defaultValue !== undefined) {
          data[pat.name] = pat.defaultValue;
        } else {
          data[pat.name] = [];
        }
      } else if (pat.defaultValue !== undefined) {
        data[pat.name] = pat.defaultValue;
      } else if (pat.type !== "boolean") {
        data[pat.name] = "";
      }
    });
    this.setState({data: data});
  }

  changeListAddElt(e, name) {
    var listAddValue = this.state.listAddValue;
    listAddValue[name] = e.target.value;
    this.setState({listAddValue: listAddValue});
  }

  AddListElt(e, name, value = false) {
    if (e) {
      e.preventDefault();
    }
    if (value) {
      var data = this.state.data;
      if (!data[name]) {
        data[name] = [];
      }
      data[name].push(value);
      this.setState({data: data});
    } else {
      if (this.state.listAddValue[name]) {
        var data = this.state.data;
        var listAddValue = this.state.listAddValue;
        if (!data[name]) {
          data[name] = [];
        }
        data[name].push(this.state.listAddValue[name]);
        this.state.listAddValue[name] = "";
        this.setState({data: data, listAddValue: listAddValue});
      }
    }
  }

  initListAdd(patternList) {
    var listAddValue = {};
    patternList.forEach((pat) => {
      if (pat.list) {
        listAddValue[pat.name] = "";
      }
    });
    return listAddValue;
  }

  initListConfirm(patternList, data) {
    var listEltConfirm = {};
    patternList.forEach((pat) => {
      if (pat.confirm) {
        listEltConfirm[pat.name] = "";
      } else if (pat.type === "password" && !!data[pat.name]) {
        listEltConfirm[pat.name] = [];
      } else if (pat.type === "jwks") {
        listEltConfirm[pat.name] = JSON.stringify(data[pat.name]);
      }
    });
    return listEltConfirm;
  }

  initListPwd(patternList, data, add) {
    var listPwd = {};
    patternList.forEach((pat) => {
      if (pat.type === "password") {
        if (Number.isInteger(data[pat.name])) {
          var len = data[pat.name];
          data[pat.name] = [];
          listPwd[pat.name] = [];
          for (var i=0; i<len; i++) {
            data[pat.name].push("");
            if (add) {
              listPwd[pat.name].push("set");
            } else {
              listPwd[pat.name].push("keep");
            }
          }
        } else if (Array.isArray(data[pat.name])) {
          var len = data[pat.name].length;
          data[pat.name] = [];
          listPwd[pat.name] = [];
          for (var i=0; i<len; i++) {
            data[pat.name].push("");
            if (add) {
              listPwd[pat.name].push("set");
            } else {
              listPwd[pat.name].push("keep");
            }
          }
        } else {
          if (add) {
            listPwd[pat.name] = "set";
          } else {
            listPwd[pat.name] = "keep";
          }
        }
      }
    });
    return listPwd;
  }

  changeTextArea(e, name, list) {
    var data = this.state.data;
    if (list) {
      data[name] = e.target.value.split("\n");
    } else {
      data[name] = e.target.value;
    }
    this.setState({data: data});
  }

  uploadFile(e, name, list) {
    var data = this.state.data;
    var file = e.target.files[0];
    var fr = new FileReader();
    fr.onload = (ev2) => {
      if (list) {
        if (!data[name]) {
          data[name] = [];
        }
        data[name].push((file.name + "/" + btoa(ev2.target.result)));
      } else {
        data[name] = file.name + "/" + btoa(ev2.target.result);
      }
      this.setState({data: data});
    };
    fr.readAsText(file);
  }

  uploadImage(e, name, list) {
    var data = this.state.data;
    var file = e.target.files[0];
    var fr = new FileReader();
    fr.onload = (ev2) => {
      if (list) {
        if (!data[name]) {
          data[name] = [];
        }
        data[name].push(btoa(ev2.target.result));
      } else {
        data[name] = btoa(ev2.target.result);
      }
      this.setState({data: data});
    };
    fr.readAsBinaryString(file);
  }

  removeImage(e, name, index) {
    var data = this.state.data;
    if (index > -1) {
      data[name].splice(index, 1);
    } else {
      delete(data[name]);
    }
    this.setState({data: data});
  }

  deleteFile(e, name, index) {
    var data = this.state.data;
    if (index > -1) {
      data[name].splice(index, 1);
    } else {
      delete(data[name]);
    }
    this.setState({data: data});
  }

  setPwd(e, name, act, index = -1) {
    e.preventDefault();
    var listPwd = this.state.listPwd;
    var data = this.state.data;
    var listEltConfirm = this.state.listEltConfirm;
    if (index >= 0) {
      listPwd[name][index] = act;
      data[name][index] = "";
      if (listEltConfirm[name] === undefined) {
        listEltConfirm[name] = [];
      }
      listEltConfirm[name][index] = "";
    } else {
      listPwd[name] = act;
      if (act === "disabled") {
        data[name] = "";
        listEltConfirm[name] = "";
      } else {
        delete(data[name]);
        delete(listEltConfirm[name]);
      }
    }
    this.setState({listPwd: listPwd, listEltConfirm: listEltConfirm, data: data});
  }

  addPassword(name) {
    var data = this.state.data;
    var listPwd = this.state.listPwd;
    var listEltConfirm = this.state.listEltConfirm;
    data[name].push("");
    listPwd[name].push("set");
    if (!listEltConfirm[name]) {
      listEltConfirm[name] = [""];
    }
    this.setState({data: data, listPwd: listPwd, listEltConfirm: listEltConfirm});
  }

  deletePasswordAt(name, index) {
    var data = this.state.data;
    data[name][index] = null;
    this.setState({data: data});
  }

  hasMultiplePasswords(source, data) {
    for (var i=0; i<source.length; i++) {
      if (data.source === source[i].name) {
        return source[i].multiple_passwords;
      }
    }
    return false;
  }
  
  exportRecord() {
    var exported = Object.assign({}, this.state.data);
    delete exported.password;
    delete exported.confirmPassword;
    var $anchor = $("#record-download");
    $anchor.attr("href", "data:application/octet-stream;base64,"+btoa(JSON.stringify(exported)));
    $anchor.attr("download", (exported.username||exported.client_id)+".json");
    $anchor[0].click();
  }
  
  importRecord() {
    $("#record-upload").click();
  }

  getImportFile(e) {
    var file = e.target.files[0];
    var fr = new FileReader();
    fr.onload = (ev2) => {
      try {
        let imported = JSON.parse(ev2.target.result);
        if (!this.state.add) {
          if (this.state.data.username) {
            imported.username = this.state.data.username;
          }
          if (this.state.data.client_id) {
            imported.client_id = this.state.data.client_id;
          }
        }
        delete imported.password;
        delete imported.confirmPassword;
        this.setState({data: imported});
      } catch (err) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.import-error")});
      }
    };
    fr.readAsText(file);
  }
  
	render() {
    var editLines = [], sourceLine = [], curSource = false, hasError;
    this.state.pattern.forEach((pat, index) => {
      var line = this.editElt(pat, this.state.data[pat.name], index);
      if (line) {
        editLines.push(line);
      }
    });
    this.state.source.forEach((source, index) => {
      if (!curSource && !source.readonly) {
        curSource = '';
      }
      if (source.name === this.state.data.source) {
        curSource = source.display_name;
      }
      if (!source.readonly || source.name === this.state.data.source) {
        sourceLine.push(<a className="dropdown-item" key={index} href="#" onClick={(e) => this.changeSource(e, source.name)}>{source.display_name||source.name}</a>);
      }
    });
    if (this.state.hasError) {
      hasError = <span className="error-input text-right">{i18next.t("admin.error-input")}</span>;
    }
    var sourceJsx = <div className="form-group">
      <div className="input-group mb-3">
        <div className="input-group-prepend">
          <label className="input-group-text" htmlFor="modal-source">{i18next.t("admin.source")}</label>
        </div>
        <div className="dropdown">
          <button className="btn btn-secondary dropdown-toggle" type="button" id="modal-source" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" disabled={!this.state.add}>
           {curSource||i18next.t("admin.source-dropdown")}
          </button>
          <div className="dropdown-menu" aria-labelledby="modal-source">
            {sourceLine}
          </div>
        </div>
      </div>
    </div>
		return (
      <div className="modal fade" id="editRecordModal" tabIndex="-1" role="dialog" aria-labelledby="editRecordModalLabel" aria-hidden="true">
        <div className="modal-dialog modal-lg" role="document">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title" id="editRecordModalLabel">{this.state.title}</h5>
              <div className="btn-group btn-icon-right" role="group">
                <button disabled={this.state.add} type="button" className="btn btn-secondary" onClick={this.exportRecord} title={i18next.t("admin.export")}>
                  <i className="fas fa-download"></i>
                </button>
                <button type="button" className="btn btn-secondary" onClick={this.importRecord} title={i18next.t("admin.import")}>
                  <i className="fas fa-upload"></i>
                </button>
              </div>
              <button type="button" className="close" aria-label={i18next.t("modal.close")} onClick={(e) => this.closeModal(e, false)}>
                <span aria-hidden="true">&times;</span>
              </button>
            </div>
            <div className="modal-body">
              <form className="needs-validation" noValidate>
                {sourceJsx}
                {editLines}
              </form>
            </div>
            <div className="modal-footer">
              {hasError}
              <button type="button" className="btn btn-secondary" onClick={(e) => this.closeModal(e, false)}>{i18next.t("modal.close")}</button>
              <button type="button" className="btn btn-primary " onClick={(e) => this.closeModal(e, true)} disabled={!this.state.data || !this.state.data.source || this.state.data.source.readonly}>{i18next.t("modal.ok")}</button>
            </div>
          </div>
        </div>
        <input type="file"
               className="upload"
               id="record-upload"
               onChange={this.getImportFile} />
        <a className="upload" id="record-download" />
      </div>
		);
	}
}

export default EditRecord;
